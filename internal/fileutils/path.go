package fileutils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// GetHomePath returns the absolute path of the provided path with the first ~
// replaced with the location of the users home directory and the path rewritten
// for the host operating system
func GetHomePath(path string) string {
	// easiest to just manually replace our separator rather than relying on filepath.Join()
	sep := fmt.Sprintf("%c", os.PathSeparator)
	p := strings.ReplaceAll(path, "/", sep)
	if strings.HasPrefix(p, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			panic(fmt.Sprintf("unable to GetHomePath: %s", path))
		}

		p = strings.Replace(p, "~", home, 1)
	}
	return filepath.Clean(p)
}

// ensures the given directory exists for the filename
// used by JsonStore and InsecureStore
func EnsureDirExists(filename string) error {
	storeDir := filepath.Dir(filename)
	f, err := os.Open(storeDir)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(storeDir, 0700); err != nil {
			return fmt.Errorf("unable to create %s: %s", storeDir, err.Error())
		}
		return nil
	} else if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("unable to stat %s: %s", storeDir, err.Error())
	}
	if !info.IsDir() {
		return fmt.Errorf("%s exists and is not a directory", storeDir)
	}
	return nil
}
