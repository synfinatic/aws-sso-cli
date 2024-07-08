package config

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigDir(t *testing.T) {
	home := os.Getenv("HOME")
	tempDir, err := os.MkdirTemp("", "")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", home)

	assert.Equal(t, tempDir+"/.config/aws-sso", ConfigDir(true))
	assert.Equal(t, "~/.config/aws-sso", ConfigDir(false))
	_ = os.MkdirAll(fmt.Sprintf("%s/.aws-sso", tempDir), 0755)
	assert.Equal(t, tempDir+"/.aws-sso", ConfigDir(true))
	assert.Equal(t, "~/.aws-sso", ConfigDir(false))
}
func TestConfigFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	os.Setenv("HOME", tempDir)
	home := os.Getenv("HOME")
	defer os.Setenv("HOME", home)

	assert.Equal(t, tempDir+"/.config/aws-sso/config.yaml", ConfigFile(true))
	assert.Equal(t, "~/.config/aws-sso/config.yaml", ConfigFile(false))
	_ = os.MkdirAll(fmt.Sprintf("%s/.aws-sso", tempDir), 0755)
	assert.Equal(t, tempDir+"/.aws-sso/config.yaml", ConfigFile(true))
	assert.Equal(t, "~/.aws-sso/config.yaml", ConfigFile(false))
}

func TestJsonStoreFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	os.Setenv("HOME", tempDir)
	home := os.Getenv("HOME")
	defer os.Setenv("HOME", home)

	assert.Equal(t, tempDir+"/.config/aws-sso/store.json", JsonStoreFile(true))
	assert.Equal(t, "~/.config/aws-sso/store.json", JsonStoreFile(false))
	_ = os.MkdirAll(fmt.Sprintf("%s/.aws-sso", tempDir), 0755)
	assert.Equal(t, tempDir+"/.aws-sso/store.json", JsonStoreFile(true))
	assert.Equal(t, "~/.aws-sso/store.json", JsonStoreFile(false))
}

func TestInsecureCacheFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	os.Setenv("HOME", tempDir)
	home := os.Getenv("HOME")
	defer os.Setenv("HOME", home)

	assert.Equal(t, tempDir+"/.config/aws-sso/cache.json", InsecureCacheFile(true))
	assert.Equal(t, "~/.config/aws-sso/cache.json", InsecureCacheFile(false))
	_ = os.MkdirAll(fmt.Sprintf("%s/.aws-sso", tempDir), 0755)
	assert.Equal(t, tempDir+"/.aws-sso/cache.json", InsecureCacheFile(true))
	assert.Equal(t, "~/.aws-sso/cache.json", InsecureCacheFile(false))
}
