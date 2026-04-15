package auditlog

import (
	"fmt"
)

// LogParserConfig holds the configuration for the log parser.
type LogParserConfig struct {
	AuditLogPath  string              `json:"audit_log_path"`
	SecretEngines []string            `json:"secret_engines"`
	Routing       map[string][]string `json:"routing"`
	OIDC          struct {
		TokenURL     string   `json:"token_url"`
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		Scopes       []string `json:"scopes"`
	} `json:"oidc"`
	StateFile      string `json:"state_file"`
	DebounceWindow string `json:"debounce_window"`
}

// ValidateConfig checks that the LogParserConfig has all required fields.
func ValidateConfig(cfg LogParserConfig) error {
	if cfg.AuditLogPath == "" {
		return fmt.Errorf("audit_log_path is required")
	}
	if len(cfg.SecretEngines) == 0 {
		return fmt.Errorf("at least one secret_engine is required")
	}
	if len(cfg.Routing) == 0 {
		return fmt.Errorf("at least one routing entry is required")
	}
	for _, engine := range cfg.SecretEngines {
		urls, ok := cfg.Routing[engine]
		if !ok || len(urls) == 0 {
			return fmt.Errorf("no route configured for engine: %s", engine)
		}
	}
	return nil
}
