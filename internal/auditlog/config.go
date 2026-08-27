package auditlog

import (
	"fmt"
)

// LogParserConfig holds the configuration for the log parser.
type LogParserConfig struct {
	AuditLogPath  string              `json:"audit_log_path"`
	SecretEngines []string            `json:"secret_engines,omitempty"`
	Routing       map[string][]string `json:"routing,omitempty"`
	OIDC          struct {
		TokenURL     string   `json:"token_url"`
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		Scopes       []string `json:"scopes"`
	} `json:"oidc"`
	StateFile      string           `json:"state_file"`
	DebounceWindow string           `json:"debounce_window"`
	Git            *GitSourceConfig `json:"git,omitempty"`
}

// ValidateConfig checks that the LogParserConfig has all required fields.
// Either a static (SecretEngines + Routing) or a git-backed (Git) routing
// source must be configured.
func ValidateConfig(cfg LogParserConfig) error {
	if cfg.AuditLogPath == "" {
		return fmt.Errorf("audit_log_path is required")
	}
	if cfg.Git != nil {
		bs := BootstrapConfig{
			AuditLogPath: cfg.AuditLogPath,
			Git:          *cfg.Git,
		}
		if err := ValidateBootstrap(bs); err != nil {
			return err
		}
		return nil
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
