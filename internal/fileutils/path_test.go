package fileutils

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnsureDirExists(t *testing.T) {
	t.Parallel()

	defer os.RemoveAll("./does_not_exist_dir")
	assert.NoError(t, EnsureDirExists("./testdata/role_tags.yaml"))
	assert.NoError(t, EnsureDirExists("./does_not_exist_dir/bar/baz/foo.yaml"))

	f, _ := os.OpenFile("./does_not_exist_dir/foo.yaml", os.O_WRONLY|os.O_CREATE, 0644)
	fmt.Fprintf(f, "data")
	f.Close()
	assert.Error(t, EnsureDirExists("./does_not_exist_dir/foo.yaml/bar"))

	_ = os.MkdirAll("./does_not_exist_dir/invalid", 0000)
	assert.Error(t, EnsureDirExists("./does_not_exist_dir/invalid/foo"))

	assert.Error(t, EnsureDirExists("/foo/bar"))
}

func TestGetHomePath(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "/", GetHomePath("/"))
	assert.Equal(t, ".", GetHomePath("."))
	assert.Equal(t, "/foo/bar", GetHomePath("/foo/bar"))
	assert.Equal(t, "/foo/bar", GetHomePath("/foo////bar"))
	assert.Equal(t, "/bar", GetHomePath("/foo/../bar"))
	home, _ := os.UserHomeDir()
	x := filepath.Join(home, "foo/bar")
	assert.Equal(t, x, GetHomePath("~/foo/bar"))
}
