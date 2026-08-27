package auditlog

import (
	"strings"
	"testing"
)

func TestValidateRouting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     RoutingConfig
		wantErr string // substring; empty = expect nil
	}{
		{
			name: "valid single engine",
			cfg: RoutingConfig{
				SecretEngines: []string{"kv"},
				Routing:       map[string][]string{"kv": {"http://raven.example"}},
			},
		},
		{
			name: "valid multiple engines and targets",
			cfg: RoutingConfig{
				SecretEngines: []string{"kv", "ssg"},
				Routing: map[string][]string{
					"kv":  {"http://raven-a.example", "http://raven-b.example"},
					"ssg": {"http://raven-c.example"},
				},
			},
		},
		{
			name: "empty engines",
			cfg: RoutingConfig{
				SecretEngines: nil,
				Routing:       map[string][]string{"kv": {"http://raven.example"}},
			},
			wantErr: "secret_engines",
		},
		{
			name: "engine missing from routing",
			cfg: RoutingConfig{
				SecretEngines: []string{"kv", "ssg"},
				Routing:       map[string][]string{"kv": {"http://raven.example"}},
			},
			wantErr: "no route configured for engine: ssg",
		},
		{
			name: "engine with empty target list",
			cfg: RoutingConfig{
				SecretEngines: []string{"kv"},
				Routing:       map[string][]string{"kv": {}},
			},
			wantErr: "no route configured for engine: kv",
		},
		{
			name: "engine with empty target URL",
			cfg: RoutingConfig{
				SecretEngines: []string{"kv"},
				Routing:       map[string][]string{"kv": {""}},
			},
			wantErr: "empty target URL",
		},
		{
			name: "duplicate engine names",
			cfg: RoutingConfig{
				SecretEngines: []string{"kv", "kv"},
				Routing:       map[string][]string{"kv": {"http://raven.example"}},
			},
			wantErr: "duplicate",
		},
		{
			name: "engine with whitespace-only target URL",
			cfg: RoutingConfig{
				SecretEngines: []string{"kv"},
				Routing:       map[string][]string{"kv": {"   "}},
			},
			wantErr: "empty target URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateRouting(tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("expected nil error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}
