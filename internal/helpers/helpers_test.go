package helpers

import (
	"testing"

	"github.com/hashicorp/vault/api"
)

func TestIsBase64(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"aGVsbG8=", true},
		{"not-base64!!!", false},
		{"", true}, // empty string is valid base64
		{"SGVsbG8gV29ybGQ=", true},
	}
	for _, tt := range tests {
		if got := IsBase64(tt.input); got != tt.want {
			t.Errorf("IsBase64(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestIsDocumentationKey(t *testing.T) {
	keys := []string{"raven/description", "docs/readme"}
	if !IsDocumentationKey(keys, "raven/description") {
		t.Error("expected true for raven/description")
	}
	if IsDocumentationKey(keys, "not-a-key") {
		t.Error("expected false for not-a-key")
	}
}

func TestKeyInDictionary(t *testing.T) {
	dict := map[string]*api.Secret{
		"exists": {},
	}
	if !KeyInDictionary(dict, "exists") {
		t.Error("expected true for existing key")
	}
	if KeyInDictionary(dict, "missing") {
		t.Error("expected false for missing key")
	}
}

func TestStringSliceContainsString(t *testing.T) {
	slice := []string{"a", "b", "c"}
	if !StringSliceContainsString(slice, "b") {
		t.Error("expected true for 'b'")
	}
	if StringSliceContainsString(slice, "d") {
		t.Error("expected false for 'd'")
	}
}

func TestFindArnDiff(t *testing.T) {
	tests := []struct {
		str1     string
		str2     string
		expected string
	}{
		{
			str1:     "arn:aws:1,arn:aws:2,arn:aws:3",
			str2:     "arn:aws:1,arn:aws:3",
			expected: "arn:aws:2",
		},
		{
			str1:     "arn:aws:1",
			str2:     "arn:aws:1",
			expected: "",
		},
	}
	for _, tt := range tests {
		got := FindArnDiff(tt.str1, tt.str2)
		if got != tt.expected {
			t.Errorf("FindArnDiff(%q, %q) = %q, want %q", tt.str1, tt.str2, got, tt.expected)
		}
	}
}

func TestEnsurePathAndReturnWritePath(t *testing.T) {
	dir := t.TempDir()
	path := EnsurePathAndReturnWritePath(dir, "myenv", "mysecret")
	expected := dir + "/declarative/myenv/sealedsecrets/mysecret.yaml"
	if path != expected {
		t.Errorf("got %s, want %s", path, expected)
	}
}

func TestGetIntEnv(t *testing.T) {
	t.Setenv("TEST_INT_ENV", "42")
	if got := GetIntEnv("TEST_INT_ENV", 0); got != 42 {
		t.Errorf("expected 42, got %d", got)
	}
	if got := GetIntEnv("NONEXISTENT_INT_ENV", 99); got != 99 {
		t.Errorf("expected 99, got %d", got)
	}
}

func TestGetBoolEnv(t *testing.T) {
	t.Setenv("TEST_BOOL_ENV", "true")
	if got := GetBoolEnv("TEST_BOOL_ENV", false); !got {
		t.Error("expected true")
	}
	if got := GetBoolEnv("NONEXISTENT_BOOL_ENV", false); got {
		t.Error("expected false")
	}
}
