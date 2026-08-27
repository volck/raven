package flock_test

import (
	"testing"

	"github.com/volck/raven/internal/flock"
)

func TestValidateProxyURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"empty", "", true},
		{"no scheme", "example.com", true},
		{"ftp", "ftp://example.com", true},
		{"javascript", "javascript:alert(1)", true},
		{"loopback", "http://127.0.0.1:8080", false},
		{"rfc1918 10/8", "http://10.0.0.1", false},
		{"rfc1918 172.16/12", "http://172.16.5.5", false},
		{"rfc1918 192.168/16", "http://192.168.1.1", false},
		{"public host", "https://raven.prod01.example", false},
		{"with path stripped", "https://raven.example/some/path", false},
		{"userinfo rejected", "https://user:pass@raven.example", true},
		{"opaque", "http:opaque", true},
		{"no host", "http:///foo", true},
		{"bad url", "://broken", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := flock.ValidateProxyURL(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateProxyURL(%q) err=%v wantErr=%v", tc.in, err, tc.wantErr)
			}
		})
	}
}
