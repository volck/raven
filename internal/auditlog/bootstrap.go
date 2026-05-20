package auditlog

import (
	"fmt"
	"time"
)

// GitSourceConfig describes how to fetch the dynamic RoutingConfig from a
// remote git repository.
type GitSourceConfig struct {
	URL                 string `json:"url"                    yaml:"url"`
	Branch              string `json:"branch"                 yaml:"branch"`
	Path                string `json:"path"                   yaml:"path"`
	PollInterval        string `json:"poll_interval"          yaml:"poll_interval"`
	SSHKeyPath          string `json:"ssh_key_path,omitempty" yaml:"ssh_key_path,omitempty"`
	KnownHostsPath      string `json:"known_hosts_path,omitempty" yaml:"known_hosts_path,omitempty"`
	InsecureSkipHostKey bool   `json:"insecure_skip_host_key,omitempty" yaml:"insecure_skip_host_key,omitempty"`
}

// BootstrapConfig is the static, on-disk configuration loaded once at startup.
// The dynamic routing portion lives in RoutingConfig and is loaded by a
// Source (typically GitSource) using BootstrapConfig.Git.
type BootstrapConfig struct {
	AuditLogPath   string          `json:"audit_log_path"            yaml:"audit_log_path"`
	HTTPAddr       string          `json:"http_addr,omitempty"       yaml:"http_addr,omitempty"`
	StateFile      string          `json:"state_file,omitempty"      yaml:"state_file,omitempty"`
	DebounceWindow string          `json:"debounce_window,omitempty" yaml:"debounce_window,omitempty"`
	OIDC           OIDCConfig      `json:"oidc"                      yaml:"oidc"`
	Git            GitSourceConfig `json:"git"                       yaml:"git"`
}

// OIDCConfig configures OIDC client-credentials authentication for dispatch.
type OIDCConfig struct {
	TokenURL     string   `json:"token_url,omitempty"     yaml:"token_url,omitempty"`
	ClientID     string   `json:"client_id,omitempty"     yaml:"client_id,omitempty"`
	ClientSecret string   `json:"client_secret,omitempty" yaml:"client_secret,omitempty"`
	Scopes       []string `json:"scopes,omitempty"        yaml:"scopes,omitempty"`
}

// ValidateBootstrap checks that the on-disk BootstrapConfig is internally
// consistent. The Git block is required (the logparser only supports
// git-backed routing).
func ValidateBootstrap(cfg BootstrapConfig) error {
	if cfg.AuditLogPath == "" {
		return fmt.Errorf("audit_log_path is required")
	}
	if cfg.Git.URL == "" {
		return fmt.Errorf("git.url is required")
	}
	if cfg.Git.Branch == "" {
		return fmt.Errorf("git.branch is required")
	}
	if cfg.Git.Path == "" {
		return fmt.Errorf("git.path is required")
	}
	if cfg.Git.PollInterval == "" {
		return fmt.Errorf("git.poll_interval is required")
	}
	d, err := time.ParseDuration(cfg.Git.PollInterval)
	if err != nil {
		return fmt.Errorf("git.poll_interval %q: %w", cfg.Git.PollInterval, err)
	}
	if d <= 0 {
		return fmt.Errorf("git.poll_interval must be > 0, got %s", d)
	}
	return nil
}
