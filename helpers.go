package main

import (
	"encoding/base64"
	"fmt"
	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
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

func getIntEnv(key string, defaultValue int) int {
	valueStr := os.Getenv(key)
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return defaultValue
}

/*
isDocumentationKey parses documentationKeys list, returns true if key exists.
*/
func isDocumentationKey(DocumentationKeys []string, key string) bool {
	for _, DocumentationKey := range DocumentationKeys {
		if DocumentationKey == key {
			log.WithFields(log.Fields{"key": key, "DocumentationKeys": DocumentationKeys}).Debug("IsdocumentationKey found key")
			return true
		}
	}
	return false
}

/*
initAdditionalKeys looks for DOCUMENTATION_KEYS in order to enrich secret object with annotation down the line.
*/
func initAdditionalKeys() (DocumentationKeys []string) {
	keys := os.Getenv("DOCUMENTATION_KEYS")
	DocumentationKeys = strings.Split(keys, ",")

	if !isDocumentationKey(DocumentationKeys, "raven/description") {
		DocumentationKeys = append(DocumentationKeys, "raven/description")
		log.WithFields(log.Fields{"DocumentationKeys": DocumentationKeys}).Info("No documentation_KEYS found, setting raven/description")

	}

	return
}

/*
WriteErrorToTerminationLog writes error message to /dev/termination-log as described in https:kubernetes.io/docs/tasks/debug-application-cluster/determine-reason-pod-failure/
*/
func WriteErrorToTerminationLog(errormsg string) {
	file, err := os.Create("/dev/termination-log")
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Fatal("WriteErrorToTerminationLog failed")

	}
	defer file.Close()

	_, err = file.WriteString(errormsg)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Fatal("writeString errormsg failed")

	}
	os.Exit(1)
}

func bindFlagAndCheckError(p *viper.Viper, flag *pflag.Flag, flagName string) {
	err := p.BindPFlag(flagName, flag)
	if err != nil {
		log.Fatalf("Failed to bind flag %s: %v", flagName, err)
	}
}
