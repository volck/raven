package auditlog

import (
	"encoding/json"
	"fmt"
	"strings"
)

// AuditEntry represents a single Vault audit log entry.
type AuditEntry struct {
	Type    string       `json:"type"`
	Request AuditRequest `json:"request"`
	Error   string       `json:"error"`
}

// AuditRequest represents the request portion of a Vault audit log entry.
type AuditRequest struct {
	ID        string `json:"id"`
	Operation string `json:"operation"`
	Path      string `json:"path"`
	MountType string `json:"mount_type"`
}

// ParseEntry parses a single NDJSON line from the Vault audit log.
func ParseEntry(line []byte) (*AuditEntry, error) {
	var entry AuditEntry
	if err := json.Unmarshal(line, &entry); err != nil {
		return nil, fmt.Errorf("failed to parse audit entry: %w", err)
	}
	return &entry, nil
}

// MatchesEngine returns true if the given path belongs to one of the configured secret engines.
func MatchesEngine(path string, engines []string) bool {
	for _, engine := range engines {
		prefix := engine + "/"
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// ExtractSecretPath extracts the secret name from a full Vault path.
// For example: "team-a-kv/data/subpath/one/mysecret" with engine "team-a-kv" returns "subpath/one/mysecret".
func ExtractSecretPath(fullPath string, engine string) string {
	// Strip the engine prefix
	rest := strings.TrimPrefix(fullPath, engine+"/")
	// Strip the KV v2 operation segment (data/, metadata/, delete/, destroy/)
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) < 2 {
		return rest
	}
	return parts[1]
}

// ClassifyOperation determines the effective operation from an audit entry.
// Returns the operation ("create", "update", "delete") and whether the entry should be processed.
// Ignores: request-type entries, entries with errors, non-kv mount types, list, and read operations.
func ClassifyOperation(entry AuditEntry) (operation string, valid bool) {
	// Only process response entries
	if entry.Type != "response" {
		return "", false
	}
	// Ignore entries with errors
	if entry.Error != "" {
		return "", false
	}
	// Only process kv mount type
	if entry.Request.MountType != "kv" {
		return "", false
	}
	// Ignore list and read operations
	if entry.Request.Operation == "list" || entry.Request.Operation == "read" {
		return "", false
	}

	path := entry.Request.Path
	// Check for soft-delete or destroy paths
	if containsPathSegment(path, "/delete/") || containsPathSegment(path, "/destroy/") {
		return "delete", true
	}

	switch entry.Request.Operation {
	case "create":
		return "create", true
	case "update":
		return "update", true
	case "delete":
		return "delete", true
	default:
		return "", false
	}
}

func containsPathSegment(path string, segment string) bool {
	return strings.Contains(path, segment)
}
