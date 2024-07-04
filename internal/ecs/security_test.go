package ecs

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecurityFilePath(t *testing.T) {
	assert.NotEqual(t, "", SecurityFilePath(WRITE_ONLY))
	assert.NotEqual(t, "", SecurityFilePath(READ_ONLY))

	home := os.Getenv("HOME")
	defer os.Setenv("HOME", home)
	os.Setenv("HOME", "")
	assert.Panics(t, func() { SecurityFilePath(WRITE_ONLY) })
}

func TestOpenSecurityFile(t *testing.T) {
	tempFile, err := os.CreateTemp("", "security_test")
	assert.NoError(t, err)
	testOpenSecurityFilePath = tempFile.Name()
	defer func() {
		testOpenSecurityFilePath = ""
		os.Remove(tempFile.Name())
	}()

	_, err = OpenSecurityFile(READ_ONLY)
	assert.NoError(t, err)

	_, err = OpenSecurityFile(WRITE_ONLY)
	assert.NoError(t, err)

	testOpenSecurityFilePath = "/dev/null/invalid"

	_, err = OpenSecurityFile(READ_ONLY)
	assert.Error(t, err)

	_, err = OpenSecurityFile(WRITE_ONLY)
	assert.Error(t, err)
}

func TestReadWriteSecurityConfig(t *testing.T) {
	f, err := os.CreateTemp("", "security_test")
	assert.NoError(t, err)

	assert.NoError(t, WriteSecurityConfig(f, "foo", "bar", "baz"))
	assert.NoError(t, f.Close())

	f, err = os.Open(f.Name())
	assert.NoError(t, err)

	values, err := ReadSecurityConfig(f)
	assert.NoError(t, err)
	assert.NoError(t, f.Close())
	assert.Equal(t, "foo", values.PrivateKey)
	assert.Equal(t, "bar", values.CertChain)
	assert.Equal(t, "baz", values.BearerToken)
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
