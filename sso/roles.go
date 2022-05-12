package sso

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2022 Aaron Turner  <synfinatic at gmail dot com>
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
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	"github.com/davecgh/go-spew/spew"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
	"github.com/synfinatic/gotable"
)

const DEFAULT_PROFILE_TEMPLATE = "{{AccountIdStr .AccountId}}:{{.RoleName}}"

// main struct holding all our Roles discovered via AWS SSO and
// via the config.yaml
type Roles struct {
	Accounts      map[int64]*AWSAccount `json:"Accounts"`
	SSORegion     string                `json:"SSORegion"`
	StartUrl      string                `json:"StartUrl"`
	DefaultRegion string                `json:"DefaultRegion"`
	ssoName       string
}

// AWSAccount and AWSRole is how we store the data
type AWSAccount struct {
	Alias         string              `json:"Alias,omitempty"` // from AWS
	Name          string              `json:"Name,omitempty"`  // from config
	EmailAddress  string              `json:"EmailAddress,omitempty"`
	Tags          map[string]string   `json:"Tags,omitempty"`
	Roles         map[string]*AWSRole `json:"Roles,omitempty"`
	DefaultRegion string              `json:"DefaultRegion,omitempty"`
}

type AWSRole struct {
	Arn           string            `json:"Arn"`
	DefaultRegion string            `json:"DefaultRegion,omitempty"`
	Expires       int64             `json:"Expires,omitempty"` // Seconds since Unix Epoch
	Profile       string            `json:"Profile,omitempty"`
	Tags          map[string]string `json:"Tags,omitempty"`
	Via           string            `json:"Via,omitempty"`
}

// AccountIds returns all the configured AWS SSO AccountIds
func (r *Roles) AccountIds() []int64 {
	ret := []int64{}
	for id := range r.Accounts {
		ret = append(ret, id)
	}
	return ret
}

// AllRoles returns all the Roles as a flat list
func (r *Roles) GetAllRoles() []*AWSRoleFlat {
	ret := []*AWSRoleFlat{}
	for _, id := range r.AccountIds() {
		for roleName := range r.Accounts[id].Roles {
			flat, _ := r.GetRole(id, roleName)
			ret = append(ret, flat)
		}
	}
	return ret
}

// GetAccountRoles returns all the roles for a given account
func (r *Roles) GetAccountRoles(accountId int64) map[string]*AWSRoleFlat {
	ret := map[string]*AWSRoleFlat{}
	account := r.Accounts[accountId]
	if account == nil {
		return ret
	}
	for roleName := range account.Roles {
		flat, _ := r.GetRole(accountId, roleName)
		ret[roleName] = flat
	}
	return ret
}

// GetAllTags returns all the unique key/tag pairs for every role
func (r *Roles) GetAllTags() *TagsList {
	ret := TagsList{}
	fList := r.GetAllRoles()
	for _, role := range fList {
		for k, v := range role.Tags {
			ret.Add(k, v)
		}
	}
	return &ret
}

// GetRoleTags returns all the tags for each role
func (r *Roles) GetRoleTags() *RoleTags {
	ret := RoleTags{}
	fList := r.GetAllRoles()
	for _, role := range fList {
		ret[role.Arn] = map[string]string{}
		for k, v := range role.Tags {
			ret[role.Arn][k] = v
		}
	}
	return &ret
}

// Role returns the specified role as an AWSRoleFlat
func (r *Roles) GetRole(accountId int64, roleName string) (*AWSRoleFlat, error) {
	account, ok := r.Accounts[accountId]
	if !ok {
		return &AWSRoleFlat{}, fmt.Errorf("invalid AWS AccountID: %d", accountId)
	}
	for thisRoleName, role := range account.Roles {
		if thisRoleName == roleName {
			flat := AWSRoleFlat{
				AccountId:     accountId,
				AccountName:   account.Name,
				AccountAlias:  account.Alias,
				EmailAddress:  account.EmailAddress,
				Expires:       role.Expires,
				Arn:           role.Arn,
				RoleName:      roleName,
				Profile:       role.Profile,
				DefaultRegion: r.DefaultRegion,
				SSO:           r.ssoName,
				SSORegion:     r.SSORegion,
				StartUrl:      r.StartUrl,
				Tags:          map[string]string{},
				Via:           role.Via,
			}

			// copy over account tags
			for k, v := range account.Tags {
				flat.Tags[k] = v
			}
			// override account values with more specific role values
			if account.DefaultRegion != "" {
				flat.DefaultRegion = account.DefaultRegion
			}
			if role.DefaultRegion != "" {
				flat.DefaultRegion = role.DefaultRegion
			}
			// Automatic tags
			flat.Tags["AccountID"], _ = utils.AccountIdToString(accountId)
			flat.Tags["Email"] = account.EmailAddress

			if account.Alias != "" {
				flat.Tags["AccountAlias"] = account.Alias
			}

			if flat.AccountName != "" {
				flat.Tags["AccountName"] = flat.AccountName
			}

			if role.Profile != "" {
				flat.Tags["Profile"] = role.Profile
			}

			if role.Via != "" {
				flat.Tags["Via"] = role.Via
			}

			// finally override role specific tags
			for k, v := range role.Tags {
				flat.Tags[k] = v
			}
			return &flat, nil
		}
	}
	return &AWSRoleFlat{}, fmt.Errorf("unable to find role %d:%s", accountId, roleName)
}

// GetRoleByProfile is just like GetRole(), but selects the role based on the Profile
func (r *Roles) GetRoleByProfile(profileName string, s *Settings) (*AWSRoleFlat, error) {
	for aId, account := range r.Accounts {
		for roleName := range account.Roles {
			flat, _ := r.GetRole(aId, roleName)
			pName, err := flat.ProfileName(s)
			if err != nil {
				log.WithError(err).Warnf(
					"unable to generate Profile for %s", utils.MakeRoleARN(aId, roleName))
			}
			if pName == profileName {
				return flat, nil
			}
		}
	}
	return &AWSRoleFlat{}, fmt.Errorf("unable to locate role with Profile: %s", profileName)
}

// GetRoleChain figures out the AssumeRole chain required to assume the given role
func (r *Roles) GetRoleChain(accountId int64, roleName string) []*AWSRoleFlat {
	ret := []*AWSRoleFlat{}

	f, err := r.GetRole(accountId, roleName)
	if err != nil {
		log.WithError(err).Fatalf("unable to get role: %s", utils.MakeRoleARN(accountId, roleName))
	}
	ret = append(ret, f)
	for f.Via != "" {
		aId, rName, err := utils.ParseRoleARN(f.Via)
		if err != nil {
			log.WithError(err).Fatalf("unable to parse '%s'", f.Via)
		}
		f, err = r.GetRole(aId, rName)
		if err != nil {
			log.WithError(err).Fatalf("unable to get role: %s", utils.MakeRoleARN(aId, rName))
		}
		ret = append([]*AWSRoleFlat{f}, ret...) // prepend
	}

	return ret
}

// MatchingRoles returns all the roles matching the given tags
func (r *Roles) MatchingRoles(tags map[string]string) []*AWSRoleFlat {
	ret := []*AWSRoleFlat{}
	for _, role := range r.GetAllRoles() {
		matches := true
		for k, v := range tags {
			if roleVal, ok := role.Tags[k]; ok {
				if roleVal != v {
					matches = false
				}
			} else {
				matches = false
			}
			if !matches {
				break
			}
		}
		if matches {
			ret = append(ret, role)
		}
	}
	return ret
}

// MatchingRolesWithTagKey returns the roles that have the tag key
func (r *Roles) MatchingRolesWithTagKey(key string) []*AWSRoleFlat {
	ret := []*AWSRoleFlat{}
	for _, role := range r.GetAllRoles() {
		for k := range role.Tags {
			if k == key {
				ret = append(ret, role)
				break
			}
		}
	}
	return ret
}

// checkProfiles verfies that all the Profile names are unique for all the defined roles
func (r *Roles) checkProfiles(s *Settings) error {
	profileUniqueCheck := map[string]string{} // ProfileName() => Arn
	for accountId, account := range r.Accounts {
		for roleName, role := range account.Roles {
			flat, err := r.GetRole(accountId, roleName)
			if err != nil {
				return err
			}

			pname, err := flat.ProfileName(s)
			if err != nil {
				return err
			}

			if arn, duplicate := profileUniqueCheck[pname]; duplicate {
				return fmt.Errorf("Duplicate profile name '%s' for:\n- %s\n- %s", pname, arn, role.Arn)
			} else {
				profileUniqueCheck[pname] = arn
			}
		}
	}
	return nil
}

// This is what we always return for a role definition
type AWSRoleFlat struct {
	Id            int               `header:"Id"`
	AccountId     int64             `json:"AccountId" header:"AccountId"`
	AccountName   string            `json:"AccountName" header:"AccountName"`
	AccountAlias  string            `json:"AccountAlias" header:"AccountAlias"`
	EmailAddress  string            `json:"EmailAddress" header:"EmailAddress"`
	Expires       int64             `json:"Expires" header:"ExpiresEpoch"`
	ExpiresStr    string            `json:"-" header:"Expires"`
	Arn           string            `json:"Arn" header:"ARN"`
	RoleName      string            `json:"RoleName" header:"Role"`
	Profile       string            `json:"Profile" header:"Profile"`
	DefaultRegion string            `json:"DefaultRegion" header:"DefaultRegion"`
	SSO           string            `json:"SSO" header:"SSO"`
	SSORegion     string            `json:"SSORegion" header:"SSORegion"`
	StartUrl      string            `json:"StartUrl" header:"StartUrl"`
	Tags          map[string]string `json:"Tags"` // not supported by GenerateTable
	Via           string            `json:"Via,omitempty" header:"Via"`
	// SelectTags    map[string]string // tags without spaces
}

func (f AWSRoleFlat) GetHeader(fieldName string) (string, error) {
	v := reflect.ValueOf(f)
	return gotable.GetHeaderTag(v, fieldName)
}

// IsExpired returns if this role has expired or has no creds available
func (r *AWSRoleFlat) IsExpired() bool {
	if r.Expires == 0 {
		return true
	}
	d := time.Until(time.Unix(r.Expires, 0))
	return d <= 0
}

// ExpiresIn returns how long until this role expires as a string
func (r *AWSRoleFlat) ExpiresIn() (string, error) {
	return utils.TimeRemain(r.Expires, false)
}

// RoleProfile returns either the user-defined Profile value for the role from
// the config.yaml or the generated Profile using the ProfileFormat template
func (r *AWSRoleFlat) ProfileName(s *Settings) (string, error) {
	if len(r.Profile) > 0 {
		return r.Profile, nil
	}

	format := s.ProfileFormat
	if len(format) == 0 {
		format = DEFAULT_PROFILE_TEMPLATE
	}

	// our custom functions
	customFuncs := template.FuncMap{
		"AccountIdStr":  accountIdToStr,
		"EmptyString":   emptyString,
		"FirstItem":     firstItem,
		"StringsJoin":   stringsJoin,
		"StringReplace": stringReplace,
	}

	// all the sprig functions
	funcMap := sprig.TxtFuncMap()
	for k, v := range customFuncs {
		funcMap[k] = v
	}

	templ, err := template.New("profile_name").Funcs(funcMap).Parse(format)
	if err != nil {
		return "", err
	}

	buf := new(bytes.Buffer)
	log.Tracef("RoleInfo: %s", spew.Sdump(r))
	log.Tracef("Template: %s", spew.Sdump(templ))
	if err := templ.Execute(buf, r); err != nil {
		return "", fmt.Errorf("unable to generate ProfileName: %s", err.Error())
	}

	return buf.String(), nil
}

func emptyString(str string) bool {
	return str == ""
}

func firstItem(items ...string) string {
	for _, v := range items {
		if v != "" {
			return v
		}
	}
	return ""
}

func accountIdToStr(id int64) string {
	i, _ := utils.AccountIdToString(id)
	return i
}

func stringsJoin(x string, items ...string) string {
	l := []string{}
	for _, v := range items {
		if len(v) > 0 {
			l = append(l, v)
		}
	}
	return strings.Join(l, x)
}

func stringReplace(search, replace, str string) string {
	return strings.ReplaceAll(str, search, replace)
}

// GetEnvVarTags returns a map containing a set of keys represening the
// environment variable names and their values
func (r *AWSRoleFlat) GetEnvVarTags(s *Settings) map[string]string {
	ret := map[string]string{}
	for k, v := range s.GetEnvVarTags() {
		if val, ok := r.Tags[k]; ok {
			ret[v] = val
		}
	}
	return ret
}

// HasPrefix determines if the given field starts with the value
// Tags, Expires and ExpiresStr are invalid
func (r *AWSRoleFlat) HasPrefix(field, prefix string) (bool, error) {
	switch field {
	case "Id":
		if strings.HasPrefix(fmt.Sprintf("%d", r.Id), prefix) {
			return true, nil
		}
	case "AccountId":
		if strings.HasPrefix(fmt.Sprintf("%d", r.AccountId), prefix) {
			return true, nil
		}
	case "AccountName":
		if strings.HasPrefix(r.AccountName, prefix) {
			return true, nil
		}
	case "AccountAlias":
		if strings.HasPrefix(r.AccountAlias, prefix) {
			return true, nil
		}
	case "EmailAddress":
		if strings.HasPrefix(r.EmailAddress, prefix) {
			return true, nil
		}
	case "Arn":
		if strings.HasPrefix(r.Arn, prefix) {
			return true, nil
		}
	case "RoleName":
		if strings.HasPrefix(r.RoleName, prefix) {
			return true, nil
		}
	case "DefaultRegion":
		if strings.HasPrefix(r.DefaultRegion, prefix) {
			return true, nil
		}
	case "Profile":
		if strings.HasPrefix(r.Profile, prefix) {
			return true, nil
		}
	case "SSO":
		if strings.HasPrefix(r.SSO, prefix) {
			return true, nil
		}
	case "SSORegion":
		if strings.HasPrefix(r.SSORegion, prefix) {
			return true, nil
		}
	case "StartUrl":
		if strings.HasPrefix(r.StartUrl, prefix) {
			return true, nil
		}
	case "Via":
		if strings.HasPrefix(r.Via, prefix) {
			return true, nil
		}
	default: // Expires, ExpiresStr & Tags
		return false, fmt.Errorf("invalid field: %s", field)
	}
	return false, nil
}
