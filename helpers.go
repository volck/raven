package main

import (
	"encoding/base64"
	"fmt"
	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
	"io/fs"
	"path/filepath"
	"strings"
	"time"
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

func parseGitStatusFileName(path string) string {
	base := fmt.Sprintf("%s/%s/%s", "declarative", newConfig.destEnv, "sealedsecrets")
	f := strings.ReplaceAll(path, base, "")
	f = strings.ReplaceAll(f, ".yaml", "")
	f = strings.ReplaceAll(f, "/", "")
	return f
}

func sleep(sleepTime int) {
	log.WithFields(log.Fields{"sleepTime": sleepTime}).Debug("Going to sleep.")
	time.Sleep(time.Duration(sleepTime) * time.Second)

	log.WithFields(log.Fields{"sleepTime": sleepTime}).Debug("Sleep done.")
}

func KeyInDictionary(dict map[string]*api.Secret, key string) bool {
	inDictionary := false
	if _, ok := dict[key]; ok {
		inDictionary = true
	}
	return inDictionary
}

func stringSliceContainsString(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
