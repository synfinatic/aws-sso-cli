package awsparse

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseRoleARN(t *testing.T) {
	t.Parallel()

	a, r, err := ParseRoleARN("arn:aws:iam::11111:role/Foo")
	assert.NoError(t, err)
	assert.Equal(t, int64(11111), a)
	assert.Equal(t, "Foo", r)

	a, r, err = ParseRoleARN("000000011111:Foo")
	assert.NoError(t, err)
	assert.Equal(t, int64(11111), a)
	assert.Equal(t, "Foo", r)

	_, _, err = ParseRoleARN("")
	assert.Error(t, err)

	_, _, err = ParseRoleARN("arnFoo")
	assert.Error(t, err)

	_, _, err = ParseRoleARN("arn:aws:iam::a:role/Foo")
	assert.Error(t, err)

	_, _, err = ParseRoleARN("arn:aws:iam::000000011111:role")
	assert.Error(t, err)

	_, _, err = ParseRoleARN("aws:iam:000000011111:role/Foo")
	assert.Error(t, err)

	_, _, err = ParseRoleARN("invalid:arn:aws:iam::000000011111:role/Foo")
	assert.Error(t, err)

	_, _, err = ParseRoleARN("arn:aws:iam::000000011111:role/Foo/Bar")
	assert.Error(t, err)

	_, _, err = ParseRoleARN("arn:aws:iam::-000000011111:role/Foo")
	assert.Error(t, err)

	// ParseUserARN is just ParseRoleARN...
	a, r, err = ParseUserARN("arn:aws:iam::22222:user/Foo")
	assert.NoError(t, err)
	assert.Equal(t, int64(22222), a)
	assert.Equal(t, "Foo", r)
}

func TestMakeRoleARN(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "arn:aws:iam::000000011111:role/Foo", MakeRoleARN(11111, "Foo"))
	assert.Equal(t, "arn:aws:iam::000000711111:role/Foo", MakeRoleARN(711111, "Foo"))
	assert.Equal(t, "arn:aws:iam::000000000000:role/", MakeRoleARN(0, ""))

	assert.Panics(t, func() { MakeRoleARN(-1, "foo") })
}

func TestMakeUserARN(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "arn:aws:iam::000000011111:user/Foo", MakeUserARN(11111, "Foo"))
	assert.Equal(t, "arn:aws:iam::000000711111:user/Foo", MakeUserARN(711111, "Foo"))
	assert.Equal(t, "arn:aws:iam::000000000000:user/", MakeUserARN(0, ""))

	assert.Panics(t, func() { MakeUserARN(-1, "foo") })
}

func TestMakeRoleARNs(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "arn:aws:iam::000000011111:role/Foo", MakeRoleARNs("11111", "Foo"))
	assert.Equal(t, "arn:aws:iam::000000711111:role/Foo", MakeRoleARNs("711111", "Foo"))
	assert.Equal(t, "arn:aws:iam::000000711111:role/Foo", MakeRoleARNs("000711111", "Foo"))
	assert.Equal(t, "arn:aws:iam::000000000000:role/", MakeRoleARNs("0", ""))

	assert.Panics(t, func() { MakeRoleARNs("asdfasfdo", "foo") })
}

func TestAccountToString(t *testing.T) {
	t.Parallel()

	a, err := AccountIdToString(0)
	assert.NoError(t, err)
	assert.Equal(t, "000000000000", a)

	a, err = AccountIdToString(11111)
	assert.NoError(t, err)
	assert.Equal(t, "000000011111", a)

	a, err = AccountIdToString(999999999999)
	assert.NoError(t, err)
	assert.Equal(t, "999999999999", a)

	_, err = AccountIdToString(-1)
	assert.Error(t, err)

	_, err = AccountIdToString(-19999)
	assert.Error(t, err)

	_, err = AccountIdToString(1000000000000)
	assert.Error(t, err)
}

func TestAccountToInt64(t *testing.T) {
	t.Parallel()

	_, err := AccountIdToInt64("")
	assert.Error(t, err)

	a, err := AccountIdToInt64("12345")
	assert.NoError(t, err)
	assert.Equal(t, int64(12345), a)

	a, err = AccountIdToInt64("0012345")
	assert.NoError(t, err)
	assert.Equal(t, int64(12345), a)

	_, err = AccountIdToInt64("0012345678912123344455323423423423424")
	assert.Error(t, err)

	_, err = AccountIdToInt64("abdcefgi")
	assert.Error(t, err)

	_, err = AccountIdToInt64("-1")
	assert.Error(t, err)

	a, err = AccountIdToInt64("7.2668187369e+10")
	assert.NoError(t, err)
	assert.Equal(t, int64(72668187369), a)

	a, err = AccountIdToInt64("1e+1")
	assert.NoError(t, err)
	assert.Equal(t, int64(10), a)

	_, err = AccountIdToInt64("10e+s4")
	assert.Error(t, err)
}
