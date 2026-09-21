// Package bitbucket is a small client for the Bitbucket Server REST API,
// covering the repository and SSH access key calls the wrangler needs.
package bitbucket

import (
	"fmt"
	"net/url"
	"strings"
)

// Repo identifies a repository by the two path segments Bitbucket Server's
// REST API addresses it with.
type Repo struct {
	ProjectKey string
	Slug       string
}

// ParseRepoURL extracts the project and slug from a clone URL. Both the ssh
// form (host:7999/sec/slug.git) and the http form (/scm/sec/slug.git) are
// accepted, so a caller can supply whichever Bitbucket showed them.
func ParseRepoURL(rawURL string) (Repo, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return Repo{}, fmt.Errorf("parse %q: %w", rawURL, err)
	}

	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	// The http clone URL prefixes the project with /scm.
	if len(segments) > 0 && segments[0] == "scm" {
		segments = segments[1:]
	}
	if len(segments) != 2 {
		return Repo{}, fmt.Errorf("repo url %q: want a project and a repository path", rawURL)
	}

	repo := Repo{
		ProjectKey: segments[0],
		Slug:       strings.TrimSuffix(segments[1], ".git"),
	}
	if repo.ProjectKey == "" || repo.Slug == "" {
		return Repo{}, fmt.Errorf("repo url %q: empty project or repository", rawURL)
	}
	return repo, nil
}
