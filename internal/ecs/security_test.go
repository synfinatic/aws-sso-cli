package ecs

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContainerSecurityFilePath(t *testing.T) {
	assert.Equal(t, CONTAINER_NAMED_FILE, ContainerSecurityFilePath())

	TestContainerFilePathOverride = "/somewhere/else"
	defer func() { TestContainerFilePathOverride = "" }()
	assert.Equal(t, "/somewhere/else", ContainerSecurityFilePath())
}

func TestHostSecurityFilePathNoHome(t *testing.T) {
	home := os.Getenv("HOME")
	defer os.Setenv("HOME", home)
	os.Setenv("HOME", "")

	// resolving the default location needs a home directory; an explicit
	// --secrets-dir does not
	assert.Panics(t, func() { HostSecurityFilePath("") })
	assert.NotPanics(t, func() { HostSecurityFilePath("/srv/secrets") })
}

func TestOpenContainerSecurityFile(t *testing.T) {
	tempFile, err := os.CreateTemp("", "security_test")
	assert.NoError(t, err)
	TestContainerFilePathOverride = tempFile.Name()
	defer func() {
		TestContainerFilePathOverride = ""
		os.Remove(tempFile.Name()) // nolint:gosec
	}()

	f, err := OpenContainerSecurityFile()
	assert.NoError(t, err)
	assert.NoError(t, f.Close())

	TestContainerFilePathOverride = "/dev/null/invalid"
	_, err = OpenContainerSecurityFile()
	assert.Error(t, err)
}

func TestReadWriteSecurityConfig(t *testing.T) {
	f, err := os.CreateTemp("", "security_test")
	assert.NoError(t, err)

	assert.NoError(t, WriteSecurityConfig(f, "foo", "bar", "baz", true, false))
	assert.NoError(t, f.Close())

	f, err = os.Open(f.Name()) // nolint:gosec
	assert.NoError(t, err)

	values, err := ReadSecurityConfig(f)
	assert.NoError(t, err)
	assert.NoError(t, f.Close())
	assert.Equal(t, "foo", values.PrivateKey)
	assert.Equal(t, "bar", values.CertChain)
	assert.Equal(t, "baz", values.BearerToken)
	assert.True(t, values.DisableSSL)
	assert.False(t, values.DisableAuth)
}

func TestReadWriteSecurityConfigDisableAuth(t *testing.T) {
	f, err := os.CreateTemp("", "security_test")
	assert.NoError(t, err)

	assert.NoError(t, WriteSecurityConfig(f, "", "", "", false, true))
	assert.NoError(t, f.Close())

	f, err = os.Open(f.Name()) // nolint:gosec
	assert.NoError(t, err)

	values, err := ReadSecurityConfig(f)
	assert.NoError(t, err)
	assert.NoError(t, f.Close())
	assert.False(t, values.DisableSSL)
	assert.True(t, values.DisableAuth)
}

func TestReadSecurityFailure(t *testing.T) {
	t.Parallel()
	f, err := os.CreateTemp("", "security_test")
	assert.NoError(t, err)
	defer os.Remove(f.Name())
	f.Close()
	_, err = ReadSecurityConfig(f)
	assert.Error(t, err)

	f, err = os.CreateTemp("", "security_test")
	assert.NoError(t, err)
	defer os.Remove(f.Name())
	_, err = f.Write([]byte("foo"))
	assert.NoError(t, err)

	_, err = f.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	_, err = ReadSecurityConfig(f)
	assert.Error(t, err)
}
