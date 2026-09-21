package bitbucket_test

import (
	"testing"

	"github.com/volck/raven/internal/bitbucket"
)

func TestParseRepoURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		url         string
		wantProject string
		wantSlug    string
	}{
		{
			name:        "ssh clone url",
			url:         "ssh://git@bitbucket.norsk-tipping.no:7999/sec/sealedsecrets-dev.git",
			wantProject: "sec",
			wantSlug:    "sealedsecrets-dev",
		},
		{
			// sealedsecrets-auth.nt.no is a real repo: only the trailing
			// .git is a suffix, the rest of the dots belong to the slug.
			name:        "slug containing dots",
			url:         "ssh://git@bitbucket.norsk-tipping.no:7999/sec/sealedsecrets-auth.nt.no.git",
			wantProject: "sec",
			wantSlug:    "sealedsecrets-auth.nt.no",
		},
		{
			name:        "http clone url has an scm prefix",
			url:         "https://bitbucket.norsk-tipping.no/scm/sec/customer-service.git",
			wantProject: "sec",
			wantSlug:    "customer-service",
		},
		{
			name:        "without the git suffix",
			url:         "ssh://git@bitbucket.norsk-tipping.no:7999/sec/sealedsecrets-int",
			wantProject: "sec",
			wantSlug:    "sealedsecrets-int",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := bitbucket.ParseRepoURL(tc.url)
			if err != nil {
				t.Fatalf("ParseRepoURL(%q) error = %v", tc.url, err)
			}
			if got.ProjectKey != tc.wantProject {
				t.Errorf("ProjectKey = %q, want %q", got.ProjectKey, tc.wantProject)
			}
			if got.Slug != tc.wantSlug {
				t.Errorf("Slug = %q, want %q", got.Slug, tc.wantSlug)
			}
		})
	}
}

func TestParseRepoURL_Rejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		url  string
	}{
		{name: "empty", url: ""},
		{name: "no path", url: "ssh://git@bitbucket.norsk-tipping.no:7999"},
		{name: "project without slug", url: "ssh://git@bitbucket.norsk-tipping.no:7999/sec"},
		{name: "empty slug", url: "ssh://git@bitbucket.norsk-tipping.no:7999/sec/.git"},
		{name: "not a url", url: "://nonsense"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got, err := bitbucket.ParseRepoURL(tc.url); err == nil {
				t.Errorf("ParseRepoURL(%q) = %+v, want error", tc.url, got)
			}
		})
	}
}
