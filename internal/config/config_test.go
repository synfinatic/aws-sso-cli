package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigDir(t *testing.T) {
	tempHome, err := os.MkdirTemp("", "")
	assert.NoError(t, err)
	defer os.RemoveAll(tempHome)

	xdg := os.Getenv("XDG_CONFIG_HOME")
	defer os.Setenv("XDG_CONFIG_HOME", xdg)
	os.Unsetenv("XDG_CONFIG_HOME")

	home := os.Getenv("HOME")
	defer os.Setenv("HOME", home)
	err = os.Setenv("HOME", tempHome)
	assert.NoError(t, err)

	assert.Equal(t, tempHome+"/.config/aws-sso", ConfigDir(true))
	assert.Equal(t, "~/.config/aws-sso", ConfigDir(false))
	_ = os.MkdirAll(fmt.Sprintf("%s/.aws-sso", tempHome), 0755)
	assert.Equal(t, tempHome+"/.aws-sso", ConfigDir(true))
	assert.Equal(t, "~/.aws-sso", ConfigDir(false))
}
func TestConfigFile(t *testing.T) {
	tempHome, err := os.MkdirTemp("", "")
	assert.NoError(t, err)
	defer os.RemoveAll(tempHome)

	xdg := os.Getenv("XDG_CONFIG_HOME")
	defer os.Setenv("XDG_CONFIG_HOME", xdg)
	os.Unsetenv("XDG_CONFIG_HOME")

	home := os.Getenv("HOME")
	defer os.Setenv("HOME", home)
	err = os.Setenv("HOME", tempHome)
	assert.NoError(t, err)

	assert.Equal(t, tempHome+"/.config/aws-sso/config.yaml", ConfigFile(true))
	assert.Equal(t, "~/.config/aws-sso/config.yaml", ConfigFile(false))
	_ = os.MkdirAll(fmt.Sprintf("%s/.aws-sso", tempHome), 0755)
	assert.Equal(t, tempHome+"/.aws-sso/config.yaml", ConfigFile(true))
	assert.Equal(t, "~/.aws-sso/config.yaml", ConfigFile(false))
}

func TestJsonStoreFile(t *testing.T) {
	tempHome, err := os.MkdirTemp("", "")
	assert.NoError(t, err)
	defer os.RemoveAll(tempHome)

	xdg := os.Getenv("XDG_CONFIG_HOME")
	defer os.Setenv("XDG_CONFIG_HOME", xdg)
	os.Unsetenv("XDG_CONFIG_HOME")

	home := os.Getenv("HOME")
	defer os.Setenv("HOME", home)
	err = os.Setenv("HOME", tempHome)
	assert.NoError(t, err)

	assert.Equal(t, tempHome+"/.config/aws-sso/store.json", JsonStoreFile(true))
	assert.Equal(t, "~/.config/aws-sso/store.json", JsonStoreFile(false))
	_ = os.MkdirAll(fmt.Sprintf("%s/.aws-sso", tempHome), 0755)
	assert.Equal(t, tempHome+"/.aws-sso/store.json", JsonStoreFile(true))
	assert.Equal(t, "~/.aws-sso/store.json", JsonStoreFile(false))
}

func TestInsecureCacheFile(t *testing.T) {
	tempHome, err := os.MkdirTemp("", "")
	assert.NoError(t, err)
	defer os.RemoveAll(tempHome)

	xdg := os.Getenv("XDG_CONFIG_HOME")
	defer os.Setenv("XDG_CONFIG_HOME", xdg)
	os.Unsetenv("XDG_CONFIG_HOME")

	home := os.Getenv("HOME")
	defer os.Setenv("HOME", home)
	err = os.Setenv("HOME", tempHome)
	assert.NoError(t, err)

	assert.Equal(t, tempHome+"/.config/aws-sso/cache.json", InsecureCacheFile(true))
	assert.Equal(t, "~/.config/aws-sso/cache.json", InsecureCacheFile(false))
	_ = os.MkdirAll(fmt.Sprintf("%s/.aws-sso", tempHome), 0755)
	assert.Equal(t, tempHome+"/.aws-sso/cache.json", InsecureCacheFile(true))
	assert.Equal(t, "~/.aws-sso/cache.json", InsecureCacheFile(false))
}

func TestXDGConfigDir(t *testing.T) {
	tempHome, err := os.MkdirTemp("", "")
	assert.NoError(t, err)
	defer os.RemoveAll(tempHome)

	xdg := os.Getenv("XDG_CONFIG_HOME")
	defer os.Setenv("XDG_CONFIG_HOME", xdg)
	os.Unsetenv("XDG_CONFIG_HOME")

	home := os.Getenv("HOME")
	defer os.Setenv("HOME", home)

	err = os.Setenv("HOME", tempHome)
	assert.NoError(t, err)

	// new config, use default XDG_CONFIG_HOME
	assert.Equal(t, filepath.Join(tempHome, ".config", "aws-sso"), ConfigDir(true))
	assert.Equal(t, "~/.config/aws-sso", ConfigDir(false))

	// use a custom XDG_CONFIG_HOME path
	os.Setenv("XDG_CONFIG_HOME", filepath.Join(tempHome, ".new-config"))
	assert.Equal(t, filepath.Join(tempHome, ".new-config", "aws-sso"), ConfigDir(true))

	// once we have the old config, we should use that though...
	err = os.MkdirAll(fmt.Sprintf("%s/.aws-sso", tempHome), 0755)
	assert.NoError(t, err)
	assert.Equal(t, filepath.Join(tempHome, "/.aws-sso"), ConfigDir(true))
	assert.Equal(t, "~/.aws-sso", ConfigDir(false))
}

func TestXDGDefaultDir(t *testing.T) {
	tempHome, err := os.MkdirTemp("", "")
	assert.NoError(t, err)
	defer os.RemoveAll(tempHome)

	home := os.Getenv("HOME")
	defer os.Setenv("HOME", home)
	err = os.Setenv("HOME", tempHome)
	assert.NoError(t, err)

	xdg := os.Getenv("XDG_CONFIG_HOME")
	defer os.Setenv("XDG_CONFIG_HOME", xdg)
	os.Setenv("XDG_CONFIG_HOME", tempHome+"/.config")

	assert.Equal(t, "~/.config/aws-sso", ConfigDir(false))
	assert.Equal(t, tempHome+"/.config/aws-sso", ConfigDir(true))
}
