package main

import (
	"encoding/base64"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	goteamsnotify "github.com/atc0005/go-teams-notify/v2"
	"github.com/atc0005/go-teams-notify/v2/adaptivecard"
	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
)

var jsonLogger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

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
	jsonLogger.Debug("Going to sleep.", "sleepTime", sleepTime)
	time.Sleep(time.Duration(sleepTime) * time.Second)

	jsonLogger.Debug("Sleep done.", "sleepTime", sleepTime)
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

func getBoolEnv(key string, defaultValue bool) bool {
	valueStr := os.Getenv(key)
	if value, err := strconv.ParseBool(valueStr); err == nil {
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
			jsonLogger.Debug("IsdocumentationKey found key", "key", key, "DocumentationKeys", DocumentationKeys)
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
		jsonLogger.Info("No documentation_KEYS found, setting raven/description", "DocumentationKeys", DocumentationKeys)
	}

	return
}

/*
WriteErrorToTerminationLog writes error message to /dev/termination-log as described in https:kubernetes.io/docs/tasks/debug-application-cluster/determine-reason-pod-failure/
*/
func WriteErrorToTerminationLog(errormsg string) {
	file, err := os.Create("/dev/termination-log")
	if err != nil {
		jsonLogger.Error("WriteErrorToTerminationLog failed", "error", err.Error())
	}
	defer file.Close()

	_, err = file.WriteString(errormsg)
	if err != nil {
		jsonLogger.Error("writeString errormsg failed", "error", err.Error())
	}
	os.Exit(1)
}

func NotifyTeamsChannel(msgTitle string, msgText string, webhookUrl string) {
	// Initialize a new Microsoft Teams client.
	mstClient := goteamsnotify.NewTeamsClient()

	// Set webhook url.
	//webhookUrl := os.Getenv("TEAMS_WEBHOOK_URL")
	//webhookUrl := "https://prod-160.westeurope.logic.azure.com:443/workflows/4b9a196d37384f238f0c38d7d7c3eb46/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=DIaGQ5KxhfxXZAr1T4oQt9_WiN4RfjyIKLeOOyj71kg"

	msg, err := adaptivecard.NewSimpleMessage(msgText, msgTitle, true)
	if err != nil {
		log.Printf(
			"failed to create message: %v",
			err,
		)
	}

	// Send the message with default timeout/retry settings.
	if err := mstClient.Send(webhookUrl, msg); err != nil {
		log.Printf(
			"failed to send message: %v",
			err,
		)
	}
}

func findArnDiff(str1, str2 string) string {
	slice1 := strings.Split(str1, ",")
	slice2 := strings.Split(str2, ",")

	start := 0
	end1 := len(slice1) - 1
	end2 := len(slice2) - 1

	// Find the first differing element from the start
	for start < len(slice1) && start < len(slice2) && slice1[start] == slice2[start] {
		start++
	}

	// Find the first differing element from the end
	for end1 >= start && end2 >= start && slice1[end1] == slice2[end2] {
		end1--
		end2--
	}

	// Extract the differing part
	if start <= end1 {
		return strings.Join(slice1[start:end1+1], ",")
	}
	return ""
}
