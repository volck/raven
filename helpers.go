package main

import (
	"encoding/base64"
	"io/fs"
	"path/filepath"
)

func isBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return false
	}
	return true
}

func makeAbsolutePath(config config, filename fs.FileInfo) (newbase string) {
	base := filepath.Join("declarative", config.destEnv, "sealedsecrets")
	newbase = base + "/" + filename.Name()
	return newbase
}
