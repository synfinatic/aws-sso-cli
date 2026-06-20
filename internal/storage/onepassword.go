//go:build cgo || windows

package storage

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2026 Aaron Turner  <synfinatic at gmail dot com>
 *
 * This program is free software: you can redistribute it
 * and/or modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or with the authors permission any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	onepassword "github.com/1password/onepassword-sdk-go"
)

// onePasswordItemsAPI is a subset of onepassword.ItemsAPI for testability.
type onePasswordItemsAPI interface {
	Create(ctx context.Context, params onepassword.ItemCreateParams) (onepassword.Item, error)
	Get(ctx context.Context, vaultID string, itemID string) (onepassword.Item, error)
	Put(ctx context.Context, item onepassword.Item) (onepassword.Item, error)
	List(ctx context.Context, vaultID string, filters ...onepassword.ItemListFilter) ([]onepassword.ItemOverview, error)
}

// onePasswordVaultsAPI is a subset of onepassword.VaultsAPI for testability.
type onePasswordVaultsAPI interface {
	List(ctx context.Context, params ...onepassword.VaultListParams) ([]onepassword.VaultOverview, error)
}

// OnePasswordStore implements SecureStorage backed by 1Password.
type OnePasswordStore struct {
	client  interface{} // keeps *onepassword.Client alive so its finalizer doesn't release the client ID
	items   onePasswordItemsAPI
	vaultID string
	itemID  string // empty until the item is first created
	version uint32 // current item version; must match server for Put to succeed
	cache   StorageData
}

// OpenOnePasswordStore creates a new OnePasswordStore. authType must be "desktop" (default)
// or "service-account". vaultName is matched case-insensitively against vault titles.
// accountName is only used when authType is "desktop".
func OpenOnePasswordStore(ctx context.Context, authType, vaultName, accountName string) (SecureStorage, error) {
	var clientOpts []onepassword.ClientOption
	switch authType {
	case OP_AUTH_DESKTOP, "":
		if accountName == "" {
			return nil, fmt.Errorf("OnePasswordAccount must be set to your 1Password account email address when using desktop auth")
		}
		clientOpts = append(clientOpts, onepassword.WithDesktopAppIntegration(accountName))
	case OP_AUTH_SERVICE:
		token := os.Getenv(ENV_OP_TOKEN)
		if token == "" {
			return nil, fmt.Errorf("%s environment variable is not set", ENV_OP_TOKEN)
		}
		clientOpts = append(clientOpts, onepassword.WithServiceAccountToken(token))
	default:
		return nil, fmt.Errorf("invalid OnePasswordAuthType %q: must be %q or %q", authType, OP_AUTH_DESKTOP, OP_AUTH_SERVICE)
	}
	clientOpts = append(clientOpts, onepassword.WithIntegrationInfo("aws-sso-cli", "v1"))

	client, err := onepassword.NewClient(ctx, clientOpts...)
	if err != nil {
		if authType == OP_AUTH_DESKTOP || authType == "" {
			log.Warn("OnePasswordAccount must be set to your 1Password account email address (e.g. \"user@example.com\")")
		}
		return nil, fmt.Errorf("unable to create 1Password client: %w", err)
	}

	return openOnePasswordStore(ctx, client, client.Items(), client.Vaults(), vaultName)
}

// openOnePasswordStore is the internal constructor used by both OpenOnePasswordStore and tests.
// anchor is stored to prevent the 1Password client from being garbage collected (its finalizer
// releases the client ID, invalidating all subsequent API calls).
func openOnePasswordStore(ctx context.Context, anchor interface{}, items onePasswordItemsAPI, vaults onePasswordVaultsAPI, vaultName string) (SecureStorage, error) {
	if vaultName == "" {
		return nil, fmt.Errorf("OnePasswordVault must be set to the name of an existing 1Password vault")
	}
	vaultID, err := resolveVaultID(ctx, vaults, vaultName)
	if err != nil {
		return nil, err
	}

	store := &OnePasswordStore{
		client:  anchor,
		items:   items,
		vaultID: vaultID,
		cache:   NewStorageData(),
	}

	overviews, err := items.List(ctx, vaultID)
	if err != nil {
		return nil, fmt.Errorf("unable to list 1Password items: %w", err)
	}

	for _, ov := range overviews {
		if ov.Title == OP_ITEM_TITLE {
			store.itemID = ov.ID
			item, err := items.Get(ctx, vaultID, ov.ID)
			if err != nil {
				return nil, fmt.Errorf("unable to get 1Password item: %w", err)
			}
			store.version = item.Version
			if err = store.loadFromItem(item); err != nil {
				return nil, err
			}
			break
		}
	}

	return store, nil
}

// resolveVaultID finds the vault ID matching vaultName (case-insensitive).
func resolveVaultID(ctx context.Context, vaults onePasswordVaultsAPI, vaultName string) (string, error) {
	all, err := vaults.List(ctx)
	if err != nil {
		return "", fmt.Errorf("unable to list 1Password vaults: %w", err)
	}
	lower := strings.ToLower(vaultName)
	for _, v := range all {
		if strings.ToLower(v.Title) == lower {
			return v.ID, nil
		}
	}
	return "", fmt.Errorf("1Password vault %q not found", vaultName)
}

// loadFromItem unmarshals the "data" field of a 1Password item into the cache.
func (op *OnePasswordStore) loadFromItem(item onepassword.Item) error {
	for _, f := range item.Fields {
		if f.ID == OP_FIELD_ID {
			if err := json.Unmarshal([]byte(f.Value), &op.cache); err != nil {
				return fmt.Errorf("unable to unmarshal 1Password storage data: %w", err)
			}
			return nil
		}
	}
	return nil // no data field yet; cache stays empty
}

// saveStorageData persists the entire in-memory cache to 1Password.
func (op *OnePasswordStore) saveStorageData(ctx context.Context) error {
	jdata, err := json.Marshal(op.cache)
	if err != nil {
		return fmt.Errorf("unable to marshal storage data: %w", err)
	}

	field := onepassword.ItemField{
		ID:        OP_FIELD_ID,
		Title:     "data",
		FieldType: onepassword.ItemFieldTypeText,
		Value:     string(jdata),
	}

	if op.itemID == "" {
		created, err := op.items.Create(ctx, onepassword.ItemCreateParams{
			Category: onepassword.ItemCategorySecureNote,
			VaultID:  op.vaultID,
			Title:    OP_ITEM_TITLE,
			Fields:   []onepassword.ItemField{field},
		})
		if err != nil {
			return fmt.Errorf("unable to create 1Password item: %w", err)
		}
		op.itemID = created.ID
		op.version = created.Version
		return nil
	}

	updated, err := op.items.Put(ctx, onepassword.Item{
		ID:       op.itemID,
		VaultID:  op.vaultID,
		Title:    OP_ITEM_TITLE,
		Category: onepassword.ItemCategorySecureNote,
		Version:  op.version,
		Fields:   []onepassword.ItemField{field},
	})
	if err != nil {
		return fmt.Errorf("unable to update 1Password item: %w", err)
	}
	op.version = updated.Version
	return nil
}

func (op *OnePasswordStore) SaveRegisterClientData(ctx context.Context, region string, client RegisterClientData) error {
	key := fmt.Sprintf("%s:%s", REGISTER_CLIENT_DATA_PREFIX, region)
	op.cache.RegisterClientData[key] = client
	return op.saveStorageData(ctx)
}

func (op *OnePasswordStore) GetRegisterClientData(region string, client *RegisterClientData) error {
	key := fmt.Sprintf("%s:%s", REGISTER_CLIENT_DATA_PREFIX, region)
	v, ok := op.cache.RegisterClientData[key]
	if !ok {
		return fmt.Errorf("no RegisterClientData for %s", region)
	}
	*client = v
	return nil
}

func (op *OnePasswordStore) DeleteRegisterClientData(ctx context.Context, region string) error {
	key := fmt.Sprintf("%s:%s", REGISTER_CLIENT_DATA_PREFIX, region)
	if _, ok := op.cache.RegisterClientData[key]; !ok {
		return fmt.Errorf("no RegisterClientData for key: %s", key)
	}
	delete(op.cache.RegisterClientData, key)
	return op.saveStorageData(ctx)
}

func (op *OnePasswordStore) SaveCreateTokenResponse(ctx context.Context, key string, token CreateTokenResponse) error {
	k := fmt.Sprintf("%s:%s", CREATE_TOKEN_RESPONSE_PREFIX, key)
	op.cache.CreateTokenResponse[k] = token
	return op.saveStorageData(ctx)
}

func (op *OnePasswordStore) GetCreateTokenResponse(key string, token *CreateTokenResponse) error {
	k := fmt.Sprintf("%s:%s", CREATE_TOKEN_RESPONSE_PREFIX, key)
	v, ok := op.cache.CreateTokenResponse[k]
	if !ok {
		return fmt.Errorf("no CreateTokenResponse for %s", k)
	}
	*token = v
	return nil
}

func (op *OnePasswordStore) DeleteCreateTokenResponse(ctx context.Context, key string) error {
	k := fmt.Sprintf("%s:%s", CREATE_TOKEN_RESPONSE_PREFIX, key)
	if _, ok := op.cache.CreateTokenResponse[k]; !ok {
		return fmt.Errorf("no CreateTokenResponse for key: %s", k)
	}
	delete(op.cache.CreateTokenResponse, k)
	return op.saveStorageData(ctx)
}

func (op *OnePasswordStore) SaveRoleCredentials(ctx context.Context, arn string, token RoleCredentials) error {
	op.cache.RoleCredentials[arn] = token
	return op.saveStorageData(ctx)
}

func (op *OnePasswordStore) GetRoleCredentials(arn string, token *RoleCredentials) error {
	v, ok := op.cache.RoleCredentials[arn]
	if !ok {
		return fmt.Errorf("no RoleCredentials for ARN: %s", arn)
	}
	*token = v
	return nil
}

func (op *OnePasswordStore) DeleteRoleCredentials(ctx context.Context, arn string) error {
	if _, ok := op.cache.RoleCredentials[arn]; !ok {
		return fmt.Errorf("no RoleCredentials for ARN: %s", arn)
	}
	delete(op.cache.RoleCredentials, arn)
	return op.saveStorageData(ctx)
}

func (op *OnePasswordStore) SaveStaticCredentials(ctx context.Context, arn string, creds StaticCredentials) error {
	op.cache.StaticCredentials[arn] = creds
	return op.saveStorageData(ctx)
}

func (op *OnePasswordStore) GetStaticCredentials(arn string, creds *StaticCredentials) error {
	v, ok := op.cache.StaticCredentials[arn]
	if !ok {
		return fmt.Errorf("no StaticCredentials for ARN: %s", arn)
	}
	*creds = v
	return nil
}

func (op *OnePasswordStore) DeleteStaticCredentials(ctx context.Context, arn string) error {
	if _, ok := op.cache.StaticCredentials[arn]; !ok {
		return fmt.Errorf("no StaticCredentials for ARN: %s", arn)
	}
	delete(op.cache.StaticCredentials, arn)
	return op.saveStorageData(ctx)
}

func (op *OnePasswordStore) ListStaticCredentials() []string {
	ret := make([]string, 0, len(op.cache.StaticCredentials))
	for k := range op.cache.StaticCredentials {
		ret = append(ret, k)
	}
	return ret
}

func (op *OnePasswordStore) SaveEcsBearerToken(ctx context.Context, token string) error {
	op.cache.EcsBearerToken = token
	return op.saveStorageData(ctx)
}

func (op *OnePasswordStore) GetEcsBearerToken() (string, error) {
	return op.cache.EcsBearerToken, nil
}

func (op *OnePasswordStore) DeleteEcsBearerToken(ctx context.Context) error {
	op.cache.EcsBearerToken = ""
	return op.saveStorageData(ctx)
}

func (op *OnePasswordStore) SaveEcsSslKeyPair(ctx context.Context, privateKey, certChain []byte) error {
	if err := ValidateSSLCertificate(certChain); err != nil {
		return err
	}
	op.cache.EcsCertChain = string(certChain)
	if err := ValidateSSLPrivateKey(privateKey); err != nil {
		return err
	}
	op.cache.EcsPrivateKey = string(privateKey)
	return op.saveStorageData(ctx)
}

func (op *OnePasswordStore) GetEcsSslCert() (string, error) {
	return op.cache.EcsCertChain, nil
}

func (op *OnePasswordStore) GetEcsSslKey() (string, error) {
	return op.cache.EcsPrivateKey, nil
}

func (op *OnePasswordStore) DeleteEcsSslKeyPair(ctx context.Context) error {
	op.cache.EcsCertChain = ""
	op.cache.EcsPrivateKey = ""
	return op.saveStorageData(ctx)
}
