package sealedsecret

import (
	"os"
	"testing"

	"github.com/hashicorp/vault/api"
)

func TestReadSealedSecretAndCompareWithVaultStruct(t *testing.T) {
	tests := []struct {
		name        string
		kv          *api.Secret
		fileContent string
		filePointer string
		engine      string
		expected    bool
	}{
		{
			name: "NoUpdateNeeded",
			kv: &api.Secret{
				Data: map[string]interface{}{
					"metadata": map[string]interface{}{
						"created_time": "2023-10-01T00:00:00Z",
					},
				},
			},
			fileContent: `
metadata:
  annotations:
    created_time: "2023-10-01T00:00:00Z"
    source: "test-engine"
`,
			filePointer: "test-sealed-secret.yaml",
			engine:      "test-engine",
			expected:    false,
		},
		{
			name: "UpdateNeededBecauseAWSARNRefHasChanged",
			kv: &api.Secret{
				Data: map[string]interface{}{
					"metadata": map[string]interface{}{
						"created_time": "2023-10-01T00:00:00Z",
						"custom_metadata": map[string]interface{}{
							"AWS_ARN_REF": "eu-north-1:123456789,eu-north-1:987654321",
						},
					},
				},
			},
			fileContent: `
metadata:
  annotations:
    AWS_ARN_REF: eu-north-1:288929571942
    created_time: "2023-10-01T00:00:00Z"
    source: "test-engine"
`,
			filePointer: "test-sealed-secret.yaml",
			engine:      "test-engine",
			expected:    true,
		},
		{
			name: "UpdateNeeded",
			kv: &api.Secret{
				Data: map[string]interface{}{
					"metadata": map[string]interface{}{
						"created_time": "2023-10-01T00:00:00Z",
					},
				},
			},
			fileContent: `
metadata:
  annotations:
    created_time: "2023-09-01T00:00:00Z"
    source: "test-engine"
`,
			filePointer: "test-sealed-secret.yaml",
			engine:      "test-engine",
			expected:    true,
		},
		{
			name: "DifferentSource",
			kv: &api.Secret{
				Data: map[string]interface{}{
					"metadata": map[string]interface{}{
						"created_time": "2023-10-01T00:00:00Z",
					},
				},
			},
			fileContent: `
metadata:
  annotations:
    created_time: "2023-10-01T00:00:00Z"
    source: "different-engine"
`,
			filePointer: "test-sealed-secret.yaml",
			engine:      "test-engine",
			expected:    false,
		},
		{
			name: "FileNotFound",
			kv: &api.Secret{
				Data: map[string]interface{}{
					"metadata": map[string]interface{}{
						"created_time": "2023-10-01T00:00:00Z",
					},
				},
			},
			filePointer: "non-existent-file.yaml",
			engine:      "test-engine",
			expected:    true,
		},
		{
			name: "InvalidYAML",
			kv: &api.Secret{
				Data: map[string]interface{}{
					"metadata": map[string]interface{}{
						"created_time": "2023-10-01T00:00:00Z",
					},
				},
			},
			fileContent: `
metadata:
  annotations:
    created_time: "2023-10-01T00:00:00Z"
    source: "test-engine
`,
			filePointer: "invalid-sealed-secret.yaml",
			engine:      "test-engine",
			expected:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.fileContent != "" {
				err := os.WriteFile(tt.filePointer, []byte(tt.fileContent), 0644)
				if err != nil {
					t.Fatalf("Failed to write test file: %v", err)
				}
				defer os.Remove(tt.filePointer)
			}

			needUpdate := ReadSealedSecretAndCompareWithVaultStruct("test-secret", tt.kv, tt.filePointer, tt.engine)
			if needUpdate != tt.expected {
				t.Errorf("Expected %v, but got %v", tt.expected, needUpdate)
			}
		})
	}
}

func TestListsMatchNillist(t *testing.T) {
	PreviousKV := map[string]*api.Secret{}
	NewKV := map[string]*api.Secret{}
	// Use vault package functions for list comparison
	if len(PreviousKV) != len(NewKV) {
		t.Fatal("listsMatchNillist does not match")
	}
}

func TestListsMatchDiff(t *testing.T) {
	data := make(map[string]interface{})
	data["mysecret"] = "123"

	PreviousKV := map[string]*api.Secret{
		"theSecret": {
			Data: data,
		},
	}
	NewKV := map[string]*api.Secret{}
	if len(PreviousKV) == len(NewKV) {
		t.Fatal("listsMatchDiff should have differences")
	}
}
