package auditlog

import (
	"fmt"
	"strings"
)

// RoutingConfig is the dynamic part of the logparser configuration that
// describes which secret engines to watch and where to dispatch their events.
// It is loaded from a Source (typically a git repository) and may be replaced
// at runtime without restarting the process.
type RoutingConfig struct {
	SecretEngines []string            `json:"secret_engines" yaml:"secret_engines"`
	Routing       map[string][]string `json:"routing"        yaml:"routing"`
}

// ValidateRouting checks that a RoutingConfig is internally consistent and
// usable. It rejects empty engine lists, duplicate engine names, engines that
// have no routing entry, and routing entries with empty target URLs.
func ValidateRouting(cfg RoutingConfig) error {
	if len(cfg.SecretEngines) == 0 {
		return fmt.Errorf("secret_engines is empty")
	}
	seen := make(map[string]bool, len(cfg.SecretEngines))
	for _, engine := range cfg.SecretEngines {
		if seen[engine] {
			return fmt.Errorf("duplicate secret_engine: %s", engine)
		}
		seen[engine] = true

		targets, ok := cfg.Routing[engine]
		if !ok || len(targets) == 0 {
			return fmt.Errorf("no route configured for engine: %s", engine)
		}
		for _, target := range targets {
			if strings.TrimSpace(target) == "" {
				return fmt.Errorf("empty target URL for engine: %s", engine)
			}
		}
	}
	return nil
}
