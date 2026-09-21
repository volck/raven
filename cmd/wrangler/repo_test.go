package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/volck/raven/internal/bitbucket"
	"github.com/volck/raven/internal/provision"
)

const testRepoURL = "ssh://git@bitbucket.example.com:7999/sec/sealedsecrets-dev.git"

const testReaderKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDnylCPIwNdp4hLwjoqn70nR1TNR5H/03/RpfcHh3MAp argocd_gitreader@example.com"

const accessKeysPath = "/rest/keys/1.0/projects/sec/repos/sealedsecrets-dev/ssh"

func testSpec() provision.RavenSpec {
	return provision.RavenSpec{
		Name:         "dev",
		Namespace:    "ssg",
		SecretEngine: "dev",
		DestEnv:      "dev",
		RepoURL:      testRepoURL,
		Image:        "raven:latest",
	}
}

type seedCall struct {
	repoURL string
	branch  string
	path    string
}

// testEnsurer wires a repoEnsurer at a stub Bitbucket and records seeding
// instead of pushing.
func testEnsurer(t *testing.T, handler http.HandlerFunc) (*repoEnsurer, *[]seedCall) {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	client, err := bitbucket.New(server.URL, "token")
	if err != nil {
		t.Fatalf("bitbucket.New: %v", err)
	}

	seeds := &[]seedCall{}
	ensurer := &repoEnsurer{
		client:    client,
		user:      "kts_builder",
		readerKey: testReaderKey,
		branch:    "master",
		seed: func(_ context.Context, repoURL, branch, path string) (bool, error) {
			*seeds = append(*seeds, seedCall{repoURL, branch, path})
			return true, nil
		},
	}
	return ensurer, seeds
}

func TestRepoEnsurer_CreatesMissingRepo(t *testing.T) {
	t.Parallel()

	var created, granted bool
	ensurer, seeds := testEnsurer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/1.0/projects/sec/repos/sealedsecrets-dev":
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/1.0/projects/sec/repos":
			created = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"slug":"sealedsecrets-dev"}`))
		case r.Method == http.MethodPut && r.URL.Path == "/rest/api/1.0/projects/sec/repos/sealedsecrets-dev/permissions/users":
			granted = true
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == accessKeysPath:
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})

	if err := ensurer.EnsureRepo(context.Background(), testSpec()); err != nil {
		t.Fatalf("EnsureRepo: %v", err)
	}
	if !created {
		t.Error("repository was not created")
	}
	if !granted {
		t.Error("write access was not granted")
	}
	if len(*seeds) != 1 {
		t.Fatalf("seed calls = %d, want 1", len(*seeds))
	}
	if want := "declarative/dev/sealedsecrets/.gitkeep"; (*seeds)[0].path != want {
		t.Errorf("seed path = %q, want %q", (*seeds)[0].path, want)
	}
	if (*seeds)[0].repoURL != testRepoURL {
		t.Errorf("seed repoURL = %q, want %q", (*seeds)[0].repoURL, testRepoURL)
	}
}

// Adopting a repository that already exists must not try to create it again.
func TestRepoEnsurer_AdoptsExistingRepo(t *testing.T) {
	t.Parallel()

	ensurer, seeds := testEnsurer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"slug":"sealedsecrets-dev","archived":false}`))
		case strings.HasSuffix(r.URL.Path, "/permissions/users"):
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == accessKeysPath:
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})

	if err := ensurer.EnsureRepo(context.Background(), testSpec()); err != nil {
		t.Fatalf("EnsureRepo: %v", err)
	}
	if len(*seeds) != 1 {
		t.Fatalf("seed calls = %d, want 1", len(*seeds))
	}
}

// Two wranglers racing on the same spec must both succeed.
func TestRepoEnsurer_ToleratesCreateRace(t *testing.T) {
	t.Parallel()

	ensurer, _ := testEnsurer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
		case r.URL.Path == "/rest/api/1.0/projects/sec/repos":
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"errors":[{"context":"name","message":"This repository URL is already taken."}]}`))
		default:
			w.WriteHeader(http.StatusCreated)
		}
	})

	if err := ensurer.EnsureRepo(context.Background(), testSpec()); err != nil {
		t.Fatalf("EnsureRepo: %v", err)
	}
}

// An archived repository accepts no pushes, so adopting one would strand the
// raven with a confusing failure later.
func TestRepoEnsurer_RejectsArchivedRepo(t *testing.T) {
	t.Parallel()

	ensurer, seeds := testEnsurer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected write to archived repository: %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"slug":"sealedsecrets-dev","archived":true}`))
	})

	err := ensurer.EnsureRepo(context.Background(), testSpec())
	if err == nil {
		t.Fatal("EnsureRepo = nil, want error for archived repository")
	}
	if len(*seeds) != 0 {
		t.Errorf("seeded an archived repository")
	}
}

// The account owning raven's key is granted write access on every repository.
func TestRepoEnsurer_GrantsUserWriteAccess(t *testing.T) {
	t.Parallel()

	var granted bool
	ensurer, seeds := testEnsurer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"slug":"sealedsecrets-dev"}`))
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/permissions/users"):
			granted = true
			if got := r.URL.Query().Get("name"); got != "kts_builder" {
				t.Errorf("name = %q, want kts_builder", got)
			}
			if got := r.URL.Query().Get("permission"); got != "REPO_WRITE" {
				t.Errorf("permission = %q, want REPO_WRITE", got)
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == accessKeysPath:
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})

	if err := ensurer.EnsureRepo(context.Background(), testSpec()); err != nil {
		t.Fatalf("EnsureRepo: %v", err)
	}
	if !granted {
		t.Error("user was not granted write access")
	}
	if len(*seeds) != 1 {
		t.Fatalf("seed calls = %d, want 1", len(*seeds))
	}
}

// Failing to grant write access must stop the provision rather than seed a
// repository raven cannot push to.
func TestRepoEnsurer_GrantFailureIsFatal(t *testing.T) {
	t.Parallel()

	ensurer, seeds := testEnsurer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":[{"message":"You are not permitted to modify permissions."}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"slug":"sealedsecrets-dev"}`))
	})

	if err := ensurer.EnsureRepo(context.Background(), testSpec()); err == nil {
		t.Fatal("EnsureRepo = nil, want error when the grant fails")
	}
	if len(*seeds) != 0 {
		t.Error("seeded a repository raven has no write access to")
	}
}

// ArgoCD reads the repository with its own key, registered as a read-only
// access key. Without it the Application cannot sync what raven pushes.
func TestRepoEnsurer_GrantsArgoReadAccess(t *testing.T) {
	t.Parallel()

	var body struct {
		Key struct {
			Text string `json:"text"`
		} `json:"key"`
		Permission string `json:"permission"`
	}
	var registered bool
	ensurer, _ := testEnsurer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"slug":"sealedsecrets-dev"}`))
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/permissions/users"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == accessKeysPath:
			registered = true
			_ = json.NewDecoder(r.Body).Decode(&body)
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})

	if err := ensurer.EnsureRepo(context.Background(), testSpec()); err != nil {
		t.Fatalf("EnsureRepo: %v", err)
	}
	if !registered {
		t.Fatal("argocd read access key was not registered")
	}
	if body.Key.Text != testReaderKey {
		t.Errorf("key text = %q, want %q", body.Key.Text, testReaderKey)
	}
	if body.Permission != "REPO_READ" {
		t.Errorf("permission = %q, want REPO_READ", body.Permission)
	}
}

// Seeding a repository ArgoCD cannot read produces a raven whose Application
// never syncs, so the failure has to surface at provision time.
func TestRepoEnsurer_ReadGrantFailureIsFatal(t *testing.T) {
	t.Parallel()

	ensurer, seeds := testEnsurer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == accessKeysPath:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":[{"message":"You are not permitted to modify this repository."}]}`))
		case r.Method == http.MethodPut:
			w.WriteHeader(http.StatusNoContent)
		default:
			_, _ = w.Write([]byte(`{"slug":"sealedsecrets-dev"}`))
		}
	})

	if err := ensurer.EnsureRepo(context.Background(), testSpec()); err == nil {
		t.Fatal("EnsureRepo = nil, want error when the read grant fails")
	}
	if len(*seeds) != 0 {
		t.Error("seeded a repository argocd cannot read")
	}
}
