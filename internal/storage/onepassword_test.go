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
	"testing"
	"time"

	onepassword "github.com/1password/onepassword-sdk-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// mockItemsAPI is a minimal in-memory implementation of onePasswordItemsAPI.
type mockItemsAPI struct {
	items       map[string]onepassword.Item // keyed by itemID
	nextID      int
	errOnCreate error
	errOnPut    error
	errOnList   error
}

func newMockItemsAPI() *mockItemsAPI {
	return &mockItemsAPI{items: map[string]onepassword.Item{}}
}

func (m *mockItemsAPI) newID() string {
	m.nextID++
	return fmt.Sprintf("item%04d", m.nextID)
}

func (m *mockItemsAPI) Create(_ context.Context, params onepassword.ItemCreateParams) (onepassword.Item, error) {
	if m.errOnCreate != nil {
		return onepassword.Item{}, m.errOnCreate
	}
	item := onepassword.Item{
		ID:       m.newID(),
		Title:    params.Title,
		Category: params.Category,
		VaultID:  params.VaultID,
		Fields:   params.Fields,
	}
	m.items[item.ID] = item
	return item, nil
}

func (m *mockItemsAPI) Get(_ context.Context, vaultID, itemID string) (onepassword.Item, error) {
	item, ok := m.items[itemID]
	if !ok || item.VaultID != vaultID {
		return onepassword.Item{}, fmt.Errorf("item not found: %s", itemID)
	}
	return item, nil
}

func (m *mockItemsAPI) Put(_ context.Context, item onepassword.Item) (onepassword.Item, error) {
	if m.errOnPut != nil {
		return onepassword.Item{}, m.errOnPut
	}
	item.Version++
	m.items[item.ID] = item
	return item, nil
}

func (m *mockItemsAPI) List(_ context.Context, vaultID string, _ ...onepassword.ItemListFilter) ([]onepassword.ItemOverview, error) {
	if m.errOnList != nil {
		return nil, m.errOnList
	}
	var out []onepassword.ItemOverview
	for _, item := range m.items {
		if item.VaultID == vaultID {
			out = append(out, onepassword.ItemOverview{ID: item.ID, Title: item.Title})
		}
	}
	return out, nil
}

// mockVaultsAPI is a minimal in-memory implementation of onePasswordVaultsAPI.
type mockVaultsAPI struct {
	vaults    []onepassword.VaultOverview
	errOnList error
}

func newMockVaultsAPI(vaultTitle, vaultID string) *mockVaultsAPI {
	return &mockVaultsAPI{
		vaults: []onepassword.VaultOverview{{ID: vaultID, Title: vaultTitle}},
	}
}

func (m *mockVaultsAPI) List(_ context.Context, _ ...onepassword.VaultListParams) ([]onepassword.VaultOverview, error) {
	if m.errOnList != nil {
		return nil, m.errOnList
	}
	return m.vaults, nil
}

const testVaultID = "testvault0001"
const testVaultName = "aws-sso-cli"

func newTestOnePasswordStore(t *testing.T) *OnePasswordStore {
	t.Helper()
	items := newMockItemsAPI()
	vaults := newMockVaultsAPI(testVaultName, testVaultID)
	s, err := openOnePasswordStore(context.Background(), nil, items, vaults, testVaultName)
	assert.NoError(t, err)
	return s.(*OnePasswordStore)
}

// --- Suite ---

type OnePasswordSuite struct {
	suite.Suite
	store SecureStorage
}

func TestOnePasswordSuite(t *testing.T) {
	s := OnePasswordSuite{}
	items := newMockItemsAPI()
	vaults := newMockVaultsAPI(testVaultName, testVaultID)
	var err error
	s.store, err = openOnePasswordStore(context.Background(), nil, items, vaults, testVaultName)
	assert.NoError(t, err)
	suite.Run(t, &s)
}

func (suite *OnePasswordSuite) TestRegisterClientData() {
	t := suite.T()
	rcd := RegisterClientData{ //nolint:gosec
		AuthorizationEndpoint: "https://example.com",
		ClientId:              "clientid",
		ClientIdIssuedAt:      time.Now().Unix(),
		ClientSecret:          "secret",
		ClientSecretExpiresAt: time.Now().Unix() + 100,
		TokenEndpoint:         "https://example.com/token",
	}
	assert.NoError(t, suite.store.SaveRegisterClientData(context.Background(), "us-east-1", rcd))

	rcd2 := RegisterClientData{}
	assert.NoError(t, suite.store.GetRegisterClientData("us-east-1", &rcd2))
	assert.Equal(t, rcd, rcd2)

	assert.NoError(t, suite.store.DeleteRegisterClientData(context.Background(), "us-east-1"))
	assert.Error(t, suite.store.GetRegisterClientData("us-east-1", &rcd2))
	assert.Error(t, suite.store.DeleteRegisterClientData(context.Background(), "missing"))
}

func (suite *OnePasswordSuite) TestCreateTokenResponse() {
	t := suite.T()
	ctr := CreateTokenResponse{
		AccessToken:  "access",
		ExpiresIn:    60,
		ExpiresAt:    time.Now().Unix() + 60,
		IdToken:      "id",
		RefreshToken: "refresh",
		TokenType:    "Bearer",
	}
	assert.NoError(t, suite.store.SaveCreateTokenResponse(context.Background(), "mykey", ctr))

	ctr2 := CreateTokenResponse{}
	assert.NoError(t, suite.store.GetCreateTokenResponse("mykey", &ctr2))
	assert.Equal(t, ctr, ctr2)

	assert.NoError(t, suite.store.DeleteCreateTokenResponse(context.Background(), "mykey"))
	assert.Error(t, suite.store.GetCreateTokenResponse("mykey", &ctr2))
	assert.Error(t, suite.store.DeleteCreateTokenResponse(context.Background(), "missing"))
}

func (suite *OnePasswordSuite) TestRoleCredentials() {
	t := suite.T()
	rc := RoleCredentials{ //nolint:gosec
		RoleName:        "MyRole",
		AccountId:       123456789012,
		AccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "token",
		Expiration:      time.Now().Unix() + 3600,
	}
	arn := "arn:aws:iam::123456789012:role/MyRole"

	assert.NoError(t, suite.store.SaveRoleCredentials(context.Background(), arn, rc))

	rc2 := RoleCredentials{}
	assert.NoError(t, suite.store.GetRoleCredentials(arn, &rc2))
	assert.Equal(t, rc, rc2)

	assert.NoError(t, suite.store.DeleteRoleCredentials(context.Background(), arn))
	assert.Error(t, suite.store.GetRoleCredentials(arn, &rc2))
	assert.Error(t, suite.store.DeleteRoleCredentials(context.Background(), "arn:aws:iam::000:role/Missing"))
}

func (suite *OnePasswordSuite) TestStaticCredentials() { //nolint:dupl
	t := suite.T()
	arn := "arn:aws:iam::123456789012:user/foobar"
	cr := StaticCredentials{ //nolint:gosec
		UserName:        "foobar",
		AccountId:       123456789012,
		AccessKeyId:     "AKID",
		SecretAccessKey: "SECRET",
	}
	assert.Empty(t, suite.store.ListStaticCredentials())

	assert.NoError(t, suite.store.SaveStaticCredentials(context.Background(), arn, cr))
	assert.Equal(t, []string{arn}, suite.store.ListStaticCredentials())

	cr2 := StaticCredentials{}
	assert.NoError(t, suite.store.GetStaticCredentials(arn, &cr2))
	assert.Equal(t, cr, cr2)

	assert.NoError(t, suite.store.DeleteStaticCredentials(context.Background(), arn))
	assert.Empty(t, suite.store.ListStaticCredentials())
	assert.Error(t, suite.store.GetStaticCredentials(arn, &cr2))
	assert.Error(t, suite.store.DeleteStaticCredentials(context.Background(), arn))
}

func (suite *OnePasswordSuite) TestEcsBearerToken() {
	t := suite.T()

	token, err := suite.store.GetEcsBearerToken()
	assert.NoError(t, err)
	assert.Empty(t, token)

	assert.NoError(t, suite.store.SaveEcsBearerToken(context.Background(), "my-bearer-token"))

	token, err = suite.store.GetEcsBearerToken()
	assert.NoError(t, err)
	assert.Equal(t, "my-bearer-token", token)

	assert.NoError(t, suite.store.DeleteEcsBearerToken(context.Background()))

	token, err = suite.store.GetEcsBearerToken()
	assert.NoError(t, err)
	assert.Empty(t, token)
}

func (suite *OnePasswordSuite) TestEcsSslKeyPair() { //nolint:dupl
	t := suite.T()

	cert, err := suite.store.GetEcsSslCert()
	assert.NoError(t, err)
	assert.Empty(t, cert)

	key, err := suite.store.GetEcsSslKey()
	assert.NoError(t, err)
	assert.Empty(t, key)

	certBytes, err := os.ReadFile("../ecs/server/testdata/localhost.crt")
	assert.NoError(t, err)
	keyBytes, err := os.ReadFile("../ecs/server/testdata/localhost.key")
	assert.NoError(t, err)

	assert.NoError(t, suite.store.SaveEcsSslKeyPair(context.Background(), []byte{}, certBytes))
	assert.NoError(t, suite.store.SaveEcsSslKeyPair(context.Background(), keyBytes, certBytes))
	assert.Error(t, suite.store.SaveEcsSslKeyPair(context.Background(), keyBytes, keyBytes))
	assert.Error(t, suite.store.SaveEcsSslKeyPair(context.Background(), certBytes, certBytes))

	cert, err = suite.store.GetEcsSslCert()
	assert.NoError(t, err)
	assert.Equal(t, string(certBytes), cert)

	key, err = suite.store.GetEcsSslKey()
	assert.NoError(t, err)
	assert.Equal(t, string(keyBytes), key)

	assert.NoError(t, suite.store.DeleteEcsSslKeyPair(context.Background()))

	cert, err = suite.store.GetEcsSslCert()
	assert.NoError(t, err)
	assert.Empty(t, cert)

	key, err = suite.store.GetEcsSslKey()
	assert.NoError(t, err)
	assert.Empty(t, key)
}

// --- Non-suite tests ---

func TestOnePasswordOpenWithExistingItem(t *testing.T) {
	// Pre-populate an item with JSON so the open loads data from it.
	initialData := NewStorageData()
	initialData.EcsBearerToken = "pre-existing-token"
	jdata, err := json.Marshal(initialData)
	assert.NoError(t, err)

	items := newMockItemsAPI()
	// Manually insert an item that would have been created in a previous run.
	preExisting := onepassword.Item{
		ID:      "existing001",
		Title:   OP_ITEM_TITLE,
		VaultID: testVaultID,
		Fields:  []onepassword.ItemField{{ID: OP_FIELD_ID, Title: "data", Value: string(jdata)}},
	}
	items.items["existing001"] = preExisting

	vaults := newMockVaultsAPI(testVaultName, testVaultID)
	store, err := openOnePasswordStore(context.Background(), nil, items, vaults, testVaultName)
	assert.NoError(t, err)

	token, err := store.GetEcsBearerToken()
	assert.NoError(t, err)
	assert.Equal(t, "pre-existing-token", token)
}

func TestOnePasswordOpenEmptyVaultName(t *testing.T) {
	items := newMockItemsAPI()
	vaults := newMockVaultsAPI(testVaultName, testVaultID)
	_, err := openOnePasswordStore(context.Background(), nil, items, vaults, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OnePasswordVault")
}

func TestOnePasswordOpenVaultNotFound(t *testing.T) {
	items := newMockItemsAPI()
	vaults := newMockVaultsAPI("some-other-vault", "vaultXXX")
	_, err := openOnePasswordStore(context.Background(), nil, items, vaults, "aws-sso-cli")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestOnePasswordOpenListError(t *testing.T) {
	items := newMockItemsAPI()
	items.errOnList = fmt.Errorf("api error")
	vaults := newMockVaultsAPI(testVaultName, testVaultID)
	_, err := openOnePasswordStore(context.Background(), nil, items, vaults, testVaultName)
	assert.Error(t, err)
}

func TestOnePasswordSaveCreateError(t *testing.T) {
	store := newTestOnePasswordStore(t)
	store.items.(*mockItemsAPI).errOnCreate = fmt.Errorf("create failed")
	err := store.SaveEcsBearerToken(context.Background(), "token")
	assert.Error(t, err)
}

func TestOnePasswordSavePutError(t *testing.T) {
	store := newTestOnePasswordStore(t)
	// First save creates the item; second save will call Put.
	assert.NoError(t, store.SaveEcsBearerToken(context.Background(), "token"))
	store.items.(*mockItemsAPI).errOnPut = fmt.Errorf("put failed")
	err := store.SaveEcsBearerToken(context.Background(), "token2")
	assert.Error(t, err)
}

func TestOnePasswordVaultListError(t *testing.T) {
	items := newMockItemsAPI()
	vaults := &mockVaultsAPI{errOnList: fmt.Errorf("vault list error")}
	_, err := openOnePasswordStore(context.Background(), nil, items, vaults, testVaultName)
	assert.Error(t, err)
}

func TestOnePasswordMissingServiceAccountToken(t *testing.T) {
	os.Unsetenv(ENV_OP_TOKEN)
	_, err := OpenOnePasswordStore(context.Background(), OP_AUTH_SERVICE, testVaultName, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), ENV_OP_TOKEN)
}

// TestOnePasswordDesktopAuthDoesNotRequireToken verifies that desktop auth does not
// require OP_SERVICE_ACCOUNT_TOKEN. Without this, the default auth type of "desktop"
// would produce a confusing "env var not set" error even for users who don't use
// service accounts.
func TestOnePasswordDesktopAuthDoesNotRequireToken(t *testing.T) {
	os.Unsetenv(ENV_OP_TOKEN)
	_, err := OpenOnePasswordStore(context.Background(), OP_AUTH_DESKTOP, testVaultName, "my-account")
	// The SDK will fail (no real desktop app in tests), but the error must not be
	// our guard message about the missing service-account token.
	if err != nil {
		assert.NotContains(t, err.Error(), ENV_OP_TOKEN)
	}
}

func TestOnePasswordInvalidAuthType(t *testing.T) {
	_, err := OpenOnePasswordStore(context.Background(), "bogus", testVaultName, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bogus")
}

func TestOnePasswordDesktopAuthRequiresAccountName(t *testing.T) {
	_, err := OpenOnePasswordStore(context.Background(), OP_AUTH_DESKTOP, testVaultName, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OnePasswordAccount")
}

func TestOnePasswordBadItemJSON(t *testing.T) {
	items := newMockItemsAPI()
	preExisting := onepassword.Item{
		ID:      "baditem001",
		Title:   OP_ITEM_TITLE,
		VaultID: testVaultID,
		Fields:  []onepassword.ItemField{{ID: OP_FIELD_ID, Title: "data", Value: "NOT VALID JSON"}},
	}
	items.items["baditem001"] = preExisting
	vaults := newMockVaultsAPI(testVaultName, testVaultID)
	_, err := openOnePasswordStore(context.Background(), nil, items, vaults, testVaultName)
	assert.Error(t, err)
}
