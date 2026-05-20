package helpers

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
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

// AnnotationSourcePath is the annotation key used to record the original
// (un-sanitized) Vault secret path on generated Kubernetes / SealedSecret
// resources. Useful for diagnosing collisions after SanitizeK8sName has been
// applied to derive metadata.name.
const AnnotationSourcePath = "raven.no/source-path"

// maxK8sNameLength is the RFC 1123 DNS subdomain maximum length used for
// most Kubernetes resource names (including Secret and SealedSecret).
const maxK8sNameLength = 253

// SanitizeK8sName converts an arbitrary string (typically a Vault secret
// path like "nt/middlearth-aws-resource-viewer-credentials-prod") into a
// valid RFC 1123 DNS subdomain suitable for use as metadata.name on a
// Kubernetes Secret or SealedSecret. The transformation is:
//   - lowercase
//   - replace any rune outside [a-z0-9.-] with '-'
//   - collapse runs of '-' into a single '-'
//   - trim leading/trailing '-' and '.'
//   - truncate to 253 chars (re-trimming the tail)
//
// If the result would be empty (e.g. input was "" or "///"), a deterministic
// fallback of the form "raven-<sha1[:8]>" is returned so the caller still
// gets a usable, stable name.
//
// The transformation is intentionally lossy: callers that need the original
// path should preserve it separately (see AnnotationSourcePath).
func SanitizeK8sName(name string) string {
	original := name
	lower := strings.ToLower(name)

	var b strings.Builder
	b.Grow(len(lower))
	prevDash := false
	for _, r := range lower {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.'
		if !ok {
			r = '-'
		}
		if r == '-' {
			if prevDash {
				continue
			}
			prevDash = true
		} else {
			prevDash = false
		}
		b.WriteRune(r)
	}
	s := strings.Trim(b.String(), "-.")
	if len(s) > maxK8sNameLength {
		s = s[:maxK8sNameLength]
		s = strings.TrimRight(s, "-.")
	}
	if s == "" {
		sum := sha1.Sum([]byte(original))
		s = "raven-" + hex.EncodeToString(sum[:])[:8]
	}
	return s
}

var JsonLogger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: true}))

func IsBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

func MakeAbsolutePath(destEnv string, filename fs.FileInfo) string {
	base := filepath.Join("declarative", destEnv, "sealedsecrets")
	return base + "/" + filename.Name()
}

func ParseGitStatusFileName(destEnv string, path string) string {
	base := fmt.Sprintf("%s/%s/%s", "declarative", destEnv, "sealedsecrets")
	f := strings.ReplaceAll(path, base, "")
	f = strings.ReplaceAll(f, ".yaml", "")
	f = strings.ReplaceAll(f, "/", "")
	return f
}

func Sleep(sleepTime int) {
	JsonLogger.Debug("Going to sleep.", "sleepTime", sleepTime)
	time.Sleep(time.Duration(sleepTime) * time.Second)
	JsonLogger.Debug("Sleep done.", "sleepTime", sleepTime)
}

func KeyInDictionary(dict map[string]*api.Secret, key string) bool {
	_, ok := dict[key]
	return ok
}

func StringSliceContainsString(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

func GetIntEnv(key string, defaultValue int) int {
	valueStr := os.Getenv(key)
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return defaultValue
}

func GetBoolEnv(key string, defaultValue bool) bool {
	valueStr := os.Getenv(key)
	if value, err := strconv.ParseBool(valueStr); err == nil {
		return value
	}
	return defaultValue
}

func IsDocumentationKey(DocumentationKeys []string, key string) bool {
	for _, DocumentationKey := range DocumentationKeys {
		if DocumentationKey == key {
			JsonLogger.Debug("IsDocumentationKey found key", "key", key, "DocumentationKeys", DocumentationKeys)
			return true
		}
	}
	return false
}

func InitAdditionalKeys() (DocumentationKeys []string) {
	keys := os.Getenv("DOCUMENTATION_KEYS")
	DocumentationKeys = strings.Split(keys, ",")

	if !IsDocumentationKey(DocumentationKeys, "raven/description") {
		DocumentationKeys = append(DocumentationKeys, "raven/description")
		JsonLogger.Info("No documentation_KEYS found, setting raven/description", "DocumentationKeys", DocumentationKeys)
	}

	return
}

func WriteErrorToTerminationLog(errormsg string) {
	file, err := os.Create("/dev/termination-log")
	if err != nil {
		JsonLogger.Error("WriteErrorToTerminationLog failed", "error", err.Error())
	}
	defer file.Close()

	_, err = file.WriteString(errormsg)
	if err != nil {
		JsonLogger.Error("writeString errormsg failed", "error", err.Error())
	}
	os.Exit(1)
}

func NotifyTeamsChannel(msgTitle string, msgText string, webhookUrl string) {
	mstClient := goteamsnotify.NewTeamsClient()

	msg, err := adaptivecard.NewSimpleMessage(msgText, msgTitle, true)
	if err != nil {
		log.Printf("failed to create message: %v", err)
	}

	if err := mstClient.Send(webhookUrl, msg); err != nil {
		log.Printf("failed to send message: %v", err)
	}
}

func FindArnDiff(str1, str2 string) string {
	slice1 := strings.Split(str1, ",")
	slice2 := strings.Split(str2, ",")

	start := 0
	end1 := len(slice1) - 1
	end2 := len(slice2) - 1

	for start < len(slice1) && start < len(slice2) && slice1[start] == slice2[start] {
		start++
	}

	for end1 >= start && end2 >= start && slice1[end1] == slice2[end2] {
		end1--
		end2--
	}

	if start <= end1 {
		return strings.Join(slice1[start:end1+1], ",")
	}
	return ""
}

func EnsurePathAndReturnWritePath(clonePath string, destEnv string, secretName string) (basePath string) {
	base := filepath.Join(clonePath, "declarative", destEnv, "sealedsecrets")
	err := os.MkdirAll(base, os.ModePerm)
	if err != nil {
		JsonLogger.Error("ensurePathAndReturnWritePath.os.Mkdir", "error", err)
	}
	if strings.HasSuffix(secretName, "/") {
		secretName = strings.Replace(secretName, "/", "", -1)
	}
	// Sanitize to prevent path traversal
	secretName = filepath.Base(secretName)
	basePath = filepath.Join(base, secretName+".yaml")
	return
}
