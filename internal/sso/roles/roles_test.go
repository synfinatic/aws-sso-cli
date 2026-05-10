package roles

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
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// mockProfileSettings satisfies ProfileSettings for testing.
type mockProfileSettings struct {
	profileFormat string
	envVarTags    map[string]string
}

func (m *mockProfileSettings) GetProfileFormat() string {
	return m.profileFormat
}

func (m *mockProfileSettings) GetEnvVarTags() map[string]string {
	return m.envVarTags
}

// --- Template helper function tests ---

func TestEmptyString(t *testing.T) {
	assert.True(t, emptyString(""))
	assert.False(t, emptyString("foo"))
}

func TestFirstItem(t *testing.T) {
	assert.Equal(t, "x", firstItem("x", "b"))
	assert.Equal(t, "x", firstItem("x"))
	assert.Equal(t, "x", firstItem("", "x", "b"))
	assert.Equal(t, "", firstItem())
}

func TestStringReplace(t *testing.T) {
	assert.Equal(t, "aaaaa", stringReplace("b", "a", "bbbbb"))
	assert.Equal(t, "zaaaaax", stringReplace("b", "a", "zbbbbbx"))
}

func TestStringsJoin(t *testing.T) {
	assert.Equal(t, "a.b.c", stringsJoin(".", "a", "b", "c"))
}

func TestAccountIdToStr(t *testing.T) {
	assert.Equal(t, "000000555555", accountIdToStr(555555))
}

// --- Standalone AWSRoleFlat tests ---

func TestAWSRoleFlatGetSortableField(t *testing.T) {
	flat := AWSRoleFlat{
		Id:           42,
		RoleName:     "foobar",
		AccountId:    12344553243,
		AccountIdPad: "012344553243",
		ExpiresEpoch: 0,
		Expires:      "Expired",
	}

	f, err := flat.GetSortableField("Id")
	assert.NoError(t, err)
	assert.Equal(t, Ival, f.Type)
	assert.Equal(t, int64(42), f.Ival)

	f, err = flat.GetSortableField("RoleName")
	assert.NoError(t, err)
	assert.Equal(t, Sval, f.Type)
	assert.Equal(t, "foobar", f.Sval)

	f, err = flat.GetSortableField("AccountId")
	assert.NoError(t, err)
	assert.Equal(t, Ival, f.Type)
	assert.Equal(t, int64(12344553243), f.Ival)

	f, err = flat.GetSortableField("AccountIdPad")
	assert.NoError(t, err)
	assert.Equal(t, Ival, f.Type)
	assert.Equal(t, int64(12344553243), f.Ival)

	f, err = flat.GetSortableField("Expires")
	assert.NoError(t, err)
	assert.Equal(t, Ival, f.Type)
	assert.Equal(t, int64(math.Pow(2, 62)), f.Ival)

	f, err = flat.GetSortableField("ExpiresEpoch")
	assert.NoError(t, err)
	assert.Equal(t, Ival, f.Type)
	assert.Equal(t, int64(math.Pow(2, 62)), f.Ival)

	_, err = flat.GetSortableField("Tags")
	assert.Error(t, err)

	_, err = flat.GetSortableField("Role")
	assert.Error(t, err)
}

func TestAWSRoleFlatGetHeader(t *testing.T) {
	f := AWSRoleFlat{}
	x, err := f.GetHeader("Expires")
	assert.NoError(t, err)
	assert.Equal(t, "Expires", x)

	x, err = f.GetHeader("ExpiresEpoch")
	assert.NoError(t, err)
	assert.Equal(t, "ExpiresEpoch", x)

	x, err = f.GetHeader("Id")
	assert.NoError(t, err)
	assert.Equal(t, "Id", x)

	x, err = f.GetHeader("Tags")
	assert.NoError(t, err)
	assert.Equal(t, "", x)
}

func TestAWSRoleFlatExpired(t *testing.T) {
	f := &AWSRoleFlat{
		ExpiresEpoch: 0,
	}
	assert.True(t, f.IsExpired())

	f = &AWSRoleFlat{
		ExpiresEpoch: 12345455,
	}
	assert.True(t, f.IsExpired())

	f = &AWSRoleFlat{
		ExpiresEpoch: time.Now().Add(time.Minute * 5).Unix(),
	}
	assert.False(t, f.IsExpired())
}

func TestAWSRoleFlatProfileName(t *testing.T) {
	s := &mockProfileSettings{profileFormat: "{{ what }}"}

	f := &AWSRoleFlat{}
	_, err := f.ProfileName(s)
	assert.Error(t, err)
}

func TestRoleFlatExpiresIn(t *testing.T) {
	f := &AWSRoleFlat{
		ExpiresEpoch: 0,
	}
	x, err := f.ExpiresIn()
	assert.NoError(t, err)
	assert.Equal(t, "Expired", x)

	f = &AWSRoleFlat{
		ExpiresEpoch: time.Now().Add(time.Minute * 5).Unix(),
	}
	x, err = f.ExpiresIn()
	assert.NoError(t, err)
	assert.Contains(t, []string{"4m", "5m"}, x)
}

func TestRoleFlatAwsRole(t *testing.T) {
	f := &AWSRoleFlat{
		Arn:           "arn:aws:iam::123456789012:role/foobar",
		DefaultRegion: "us-east-1",
		ExpiresEpoch:  923452345,
		Profile:       "foobar",
		Tags: map[string]string{
			"Foo": "bar",
		},
		Via: "arn:aws:iam::123456789012:role/foobarSource",
	}
	x := f.AwsRole()
	assert.Equal(t, AWSRole{
		Arn:           "arn:aws:iam::123456789012:role/foobar",
		DefaultRegion: "us-east-1",
		Expires:       923452345,
		Profile:       "foobar",
		Tags: map[string]string{
			"Foo": "bar",
		},
		Via: "arn:aws:iam::123456789012:role/foobarSource",
	}, *x)
}

func TestAWSRoleFlatHasPrefix(t *testing.T) {
	f := &AWSRoleFlat{
		Id:            10,
		AccountId:     555555,
		AccountIdPad:  "000000555555",
		AccountName:   "testing account",
		AccountAlias:  "testing",
		EmailAddress:  "testing+aws@company.com",
		Arn:           "arn:aws:iam::555555:role/Testing",
		RoleName:      "Testing",
		DefaultRegion: "us-east-1",
		Profile:       "Testing",
		SSO:           "Main",
		SSORegion:     "us-west-2",
		StartUrl:      "https://test.awsapps.com/start",
		Via:           "arn:aws:iam::555555:role/Foobar",
	}

	// invalid key
	invalid := map[string]string{
		"X":            "test",
		"Expires":      "foo",
		"ExpiresEpoch": "bar",
		"Tags":         "baz",
	}
	for k, v := range invalid {
		_, err := f.HasPrefix(k, v)
		assert.Error(t, err)
	}

	valid := map[string]string{
		"Id":            "1",
		"AccountId":     "55",
		"AccountIdPad":  "00000055",
		"AccountName":   "testing",
		"AccountAlias":  "test",
		"EmailAddress":  "testing+aws@company.",
		"Arn":           "arn:aws",
		"RoleName":      "Test",
		"DefaultRegion": "us-",
		"Profile":       "T",
		"SSO":           "Ma",
		"SSORegion":     "us-we",
		"StartUrl":      "https",
		"Via":           "arn:",
	}

	for k, v := range valid {
		ret, err := f.HasPrefix(k, v)
		assert.NoError(t, err)
		assert.True(t, ret)
	}

	falseValues := map[string]string{
		"Id":           "55",
		"EmailAddress": "bingo",
		"SSO":          "wtf?",
		"StartUrl":     "123344",
	}

	for k, v := range falseValues {
		ret, err := f.HasPrefix(k, v)
		assert.NoError(t, err)
		assert.False(t, ret)
	}

	v, err := f.HasPrefix("Via", "x")
	assert.NoError(t, err)
	assert.False(t, v)
}

// --- Roles method tests ---

// testRolesFixture builds an in-memory Roles struct for testing Roles methods.
func testRolesFixture() *Roles {
	return &Roles{
		SSORegion:     "us-east-1",
		StartUrl:      "https://example.awsapps.com/start",
		DefaultRegion: "us-east-1",
		SSOName:       "TestSSO",
		Accounts: map[int64]*AWSAccount{
			111111111111: {
				Name:         "dev-account",
				Alias:        "dev",
				EmailAddress: "dev@example.com",
				Tags:         map[string]string{"Env": "dev"},
				Roles: map[string]*AWSRole{
					"DevAdmin": {
						Arn:     "arn:aws:iam::111111111111:role/DevAdmin",
						Profile: "dev-admin",
						Tags:    map[string]string{},
					},
					"DevReadOnly": {
						Arn:  "arn:aws:iam::111111111111:role/DevReadOnly",
						Tags: map[string]string{"Access": "readonly"},
					},
				},
			},
			222222222222: {
				Name:          "prod-account",
				Alias:         "prod",
				EmailAddress:  "prod@example.com",
				Tags:          map[string]string{"Env": "prod"},
				DefaultRegion: "eu-west-1",
				Roles: map[string]*AWSRole{
					"ProdAdmin": {
						Arn: "arn:aws:iam::222222222222:role/ProdAdmin",
						Via: "arn:aws:iam::111111111111:role/DevAdmin",
					},
				},
			},
		},
	}
}

func TestRolesAccountIds(t *testing.T) {
	r := testRolesFixture()
	ids := r.AccountIds()
	assert.Len(t, ids, 2)
	assert.Contains(t, ids, int64(111111111111))
	assert.Contains(t, ids, int64(222222222222))
}

func TestRolesGetAllRoles(t *testing.T) {
	r := testRolesFixture()
	all := r.GetAllRoles()
	assert.Len(t, all, 3)
}

func TestRolesGetAccountRoles(t *testing.T) {
	r := testRolesFixture()

	roles := r.GetAccountRoles(111111111111)
	assert.Len(t, roles, 2)
	assert.Contains(t, roles, "DevAdmin")
	assert.Contains(t, roles, "DevReadOnly")

	// missing account returns empty map
	empty := r.GetAccountRoles(999999999999)
	assert.Empty(t, empty)
}

func TestRolesGetAllTags(t *testing.T) {
	r := testRolesFixture()
	tags := r.GetAllTags()
	assert.NotNil(t, tags)
}

func TestRolesGetRoleTags(t *testing.T) {
	r := testRolesFixture()
	rt := r.GetRoleTags()
	assert.NotNil(t, rt)
	assert.Contains(t, *rt, "arn:aws:iam::111111111111:role/DevAdmin")
	assert.Contains(t, *rt, "arn:aws:iam::111111111111:role/DevReadOnly")
	assert.Contains(t, *rt, "arn:aws:iam::222222222222:role/ProdAdmin")
}

func TestRolesGetRole(t *testing.T) {
	r := testRolesFixture()

	// valid role — check all auto-populated fields and tags
	flat, err := r.GetRole(111111111111, "DevAdmin")
	assert.NoError(t, err)
	assert.Equal(t, "arn:aws:iam::111111111111:role/DevAdmin", flat.Arn)
	assert.Equal(t, "DevAdmin", flat.RoleName)
	assert.Equal(t, "dev-account", flat.AccountName)
	assert.Equal(t, "dev", flat.AccountAlias)
	assert.Equal(t, "dev@example.com", flat.EmailAddress)
	assert.Equal(t, "111111111111", flat.AccountIdPad)
	assert.Equal(t, "us-east-1", flat.DefaultRegion)
	assert.Equal(t, "TestSSO", flat.SSO)
	assert.Equal(t, "dev-admin", flat.Profile)
	assert.Equal(t, "Expired", flat.Expires) // zero ExpiresEpoch
	assert.Equal(t, "dev", flat.Tags["Env"])
	assert.Equal(t, "111111111111", flat.Tags["AccountID"])
	assert.Equal(t, "dev@example.com", flat.Tags["Email"])
	assert.Equal(t, "dev", flat.Tags["AccountAlias"])
	assert.Equal(t, "dev-account", flat.Tags["AccountName"])
	assert.Equal(t, "dev-admin", flat.Tags["Profile"])

	// account-level DefaultRegion override
	flat, err = r.GetRole(222222222222, "ProdAdmin")
	assert.NoError(t, err)
	assert.Equal(t, "eu-west-1", flat.DefaultRegion)
	assert.Equal(t, "arn:aws:iam::111111111111:role/DevAdmin", flat.Via)
	assert.Equal(t, "arn:aws:iam::111111111111:role/DevAdmin", flat.Tags["Via"])

	// role-level tag override
	flat, err = r.GetRole(111111111111, "DevReadOnly")
	assert.NoError(t, err)
	assert.Equal(t, "readonly", flat.Tags["Access"])

	// invalid account
	_, err = r.GetRole(999999999999, "DevAdmin")
	assert.Error(t, err)

	// invalid role name
	_, err = r.GetRole(111111111111, "NoSuchRole")
	assert.Error(t, err)
}

func TestRolesGetRoleByProfile(t *testing.T) {
	r := testRolesFixture()
	s := &mockProfileSettings{profileFormat: DEFAULT_PROFILE_TEMPLATE}

	// DevAdmin has an explicit Profile field set
	flat, err := r.GetRoleByProfile("dev-admin", s)
	assert.NoError(t, err)
	assert.Equal(t, "DevAdmin", flat.RoleName)

	// DevReadOnly has no Profile, so it uses the template
	flat, err = r.GetRoleByProfile("111111111111:DevReadOnly", s)
	assert.NoError(t, err)
	assert.Equal(t, "DevReadOnly", flat.RoleName)

	_, err = r.GetRoleByProfile("no-such-profile", s)
	assert.Error(t, err)
}

func TestRolesGetRoleChain(t *testing.T) {
	r := testRolesFixture()

	// single role with no Via
	chain := r.GetRoleChain(111111111111, "DevAdmin")
	assert.Len(t, chain, 1)
	assert.Equal(t, "DevAdmin", chain[0].RoleName)

	// ProdAdmin has Via → DevAdmin, so chain is [DevAdmin, ProdAdmin]
	chain = r.GetRoleChain(222222222222, "ProdAdmin")
	assert.Len(t, chain, 2)
	assert.Equal(t, "DevAdmin", chain[0].RoleName)
	assert.Equal(t, "ProdAdmin", chain[1].RoleName)
}

func TestRolesMatchingRoles(t *testing.T) {
	r := testRolesFixture()

	// both dev roles carry the Env=dev account tag
	matches := r.MatchingRoles(map[string]string{"Env": "dev"})
	assert.Len(t, matches, 2)

	// only DevReadOnly has Access=readonly
	matches = r.MatchingRoles(map[string]string{"Access": "readonly"})
	assert.Len(t, matches, 1)
	assert.Equal(t, "DevReadOnly", matches[0].RoleName)

	// no match
	matches = r.MatchingRoles(map[string]string{"Env": "staging"})
	assert.Empty(t, matches)
}

func TestRolesMatchingRolesWithTagKey(t *testing.T) {
	r := testRolesFixture()

	matches := r.MatchingRolesWithTagKey("Access")
	assert.Len(t, matches, 1)
	assert.Equal(t, "DevReadOnly", matches[0].RoleName)

	matches = r.MatchingRolesWithTagKey("NoSuchKey")
	assert.Empty(t, matches)
}

func TestRolesCheckProfiles(t *testing.T) {
	r := testRolesFixture()

	// default template: AccountIdPad:RoleName — all unique
	s := &mockProfileSettings{profileFormat: DEFAULT_PROFILE_TEMPLATE}
	assert.NoError(t, r.CheckProfiles(s))

	// two roles with the same explicit Profile value → duplicate error
	rDup := &Roles{
		DefaultRegion: "us-east-1",
		SSOName:       "TestSSO",
		Accounts: map[int64]*AWSAccount{
			111111111111: {
				Name: "dev-account",
				Roles: map[string]*AWSRole{
					"Role1": {
						Arn:     "arn:aws:iam::111111111111:role/Role1",
						Profile: "same-profile",
					},
					"Role2": {
						Arn:     "arn:aws:iam::111111111111:role/Role2",
						Profile: "same-profile",
					},
				},
			},
		},
	}
	assert.Error(t, rDup.CheckProfiles(s))
}

func TestAWSRoleFlatGetEnvVarTags(t *testing.T) {
	r := testRolesFixture()
	flat, err := r.GetRole(111111111111, "DevAdmin")
	assert.NoError(t, err)

	s := &mockProfileSettings{
		envVarTags: map[string]string{
			"Env":    "AWS_ENV",
			"NoSuch": "AWS_NO_SUCH",
		},
	}
	result := flat.GetEnvVarTags(s)
	assert.Equal(t, map[string]string{"AWS_ENV": "dev"}, result)
}

func TestAWSRoleFlatProfileNameWithProfile(t *testing.T) {
	s := &mockProfileSettings{profileFormat: DEFAULT_PROFILE_TEMPLATE}
	f := &AWSRoleFlat{Profile: "my-explicit-profile"}
	name, err := f.ProfileName(s)
	assert.NoError(t, err)
	assert.Equal(t, "my-explicit-profile", name)
}
