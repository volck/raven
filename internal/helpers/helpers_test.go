package helpers

import (
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"
)

// rfc1123Subdomain matches the Kubernetes DNS subdomain pattern used for
// metadata.name on Secret/SealedSecret resources.
var rfc1123Subdomain = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

func TestSanitizeK8sName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"real failing case", "nt/middlearth-aws-resource-viewer-credentials-prod", "nt-middlearth-aws-resource-viewer-credentials-prod"},
		{"multiple slashes", "nt/foo/bar/baz", "nt-foo-bar-baz"},
		{"uppercase and dot", "Team_A/My.Secret", "team-a-my.secret"},
		{"underscores", "custom_metadataSecret", "custom-metadatasecret"},
		{"leading and trailing slashes", "/leading/slash/", "leading-slash"},
		{"double slashes collapse", "nt//foo", "nt-foo"},
		{"trailing dots trimmed", "foo...", "foo"},
		{"leading dots trimmed", "...foo", "foo"},
		{"already valid", "foo-bar.baz", "foo-bar.baz"},
		{"digits at start allowed", "123-foo", "123-foo"},
		{"single char", "a", "a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeK8sName(tt.in)
			if got != tt.want {
				t.Errorf("SanitizeK8sName(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if !rfc1123Subdomain.MatchString(got) {
				t.Errorf("SanitizeK8sName(%q) = %q does not match RFC 1123 subdomain", tt.in, got)
			}
		})
	}
}

func TestSanitizeK8sName_LengthCap(t *testing.T) {
	in := strings.Repeat("a", 300)
	got := SanitizeK8sName(in)
	if len(got) != 253 {
		t.Errorf("length = %d, want 253", len(got))
	}
	if !rfc1123Subdomain.MatchString(got) {
		t.Errorf("%q is not a valid RFC 1123 subdomain", got)
	}
}

func TestSanitizeK8sName_LengthCapTrimsTail(t *testing.T) {
	// 252 'a's followed by enough '/' to push past 253; after replacement
	// to '-' and length cap, the tail should be trimmed of '-'.
	in := strings.Repeat("a", 252) + "////////"
	got := SanitizeK8sName(in)
	if strings.HasSuffix(got, "-") || strings.HasSuffix(got, ".") {
		t.Errorf("got %q must not end with '-' or '.'", got)
	}
	if !rfc1123Subdomain.MatchString(got) {
		t.Errorf("%q is not a valid RFC 1123 subdomain", got)
	}
}

func TestSanitizeK8sName_FallbackForEmpty(t *testing.T) {
	cases := []string{"", "///", "...", "_-_-_"}
	for _, in := range cases {
		got := SanitizeK8sName(in)
		if !strings.HasPrefix(got, "raven-") {
			t.Errorf("SanitizeK8sName(%q) = %q, expected fallback with raven- prefix", in, got)
		}
		if !rfc1123Subdomain.MatchString(got) {
			t.Errorf("fallback %q is not a valid RFC 1123 subdomain", got)
		}
	}
}

func TestSanitizeK8sName_Deterministic(t *testing.T) {
	in := "nt/middlearth-aws-resource-viewer-credentials-prod"
	a := SanitizeK8sName(in)
	b := SanitizeK8sName(in)
	if a != b {
		t.Errorf("not deterministic: %q vs %q", a, b)
	}
}

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
