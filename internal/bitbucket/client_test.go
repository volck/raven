package bitbucket_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/volck/raven/internal/bitbucket"
)

const testToken = "super-secret-bitbucket-token"

func TestClient_EnsurePullRequest(t *testing.T) {
	t.Parallel()
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "create", true: "reuse"}[existing], func(t *testing.T) {
			posts := 0
			client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/rest/api/1.0/projects/GIT/repos/bender/pull-requests" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer "+testToken {
					t.Error("missing bearer authentication")
				}
				if r.Method == http.MethodGet {
					if r.URL.Query().Get("state") != "OPEN" || r.URL.Query().Get("at") != "refs/heads/raven/create-demo" || r.URL.Query().Get("direction") != "OUTGOING" {
						t.Errorf("unexpected query: %s", r.URL.RawQuery)
					}
					if existing {
						_, _ = io.WriteString(w, `{"values":[{"id":42,"fromRef":{"id":"refs/heads/raven/create-demo","repository":{"slug":"bender","project":{"key":"GIT"}}},"toRef":{"id":"refs/heads/master"}}],"isLastPage":true}`)
					} else {
						_, _ = io.WriteString(w, `{"values":[],"isLastPage":true}`)
					}
					return
				}
				posts++
				var body struct {
					Title   string `json:"title"`
					FromRef struct {
						ID         string               `json:"id"`
						Repository bitbucket.Repository `json:"repository"`
					} `json:"fromRef"`
					ToRef struct {
						ID string `json:"id"`
					} `json:"toRef"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if r.Method != http.MethodPost || body.Title != "Add ArgoCD Application for raven demo" || body.FromRef.ID != "refs/heads/raven/create-demo" || body.ToRef.ID != "refs/heads/master" || body.FromRef.Repository.Slug != "bender" || body.FromRef.Repository.Project.Key != "GIT" {
					t.Errorf("unexpected PR request: %+v", body)
				}
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, `{"id":42}`)
			})
			link, err := client.EnsurePullRequest(context.Background(), bitbucket.Repo{ProjectKey: "GIT", Slug: "bender"}, "raven/create-demo", "master", "Add ArgoCD Application for raven demo")
			if err != nil || !strings.HasSuffix(link, "/projects/GIT/repos/bender/pull-requests/42") {
				t.Fatalf("link=%q err=%v", link, err)
			}
			if (existing && posts != 0) || (!existing && posts != 1) {
				t.Fatalf("unexpected POST count: %d", posts)
			}
		})
	}
}

func testClient(t *testing.T, handler http.HandlerFunc) *bitbucket.Client {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	client, err := bitbucket.New(srv.URL, testToken)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return client
}

func TestClient_EnsurePullRequest_Pagination(t *testing.T) {
	t.Parallel()
	gets := 0
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Error("should reuse the PR on the second page")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		gets++
		if r.URL.Query().Get("start") == "0" {
			_, _ = io.WriteString(w, `{"values":[{"id":1,"fromRef":{"id":"refs/heads/feature","repository":{"slug":"fork","project":{"key":"OTHER"}}},"toRef":{"id":"refs/heads/master"}},{"id":2,"fromRef":{"id":"refs/heads/feature","repository":{"slug":"bender","project":{"key":"GIT"}}},"toRef":{"id":"refs/heads/other"}}],"isLastPage":false,"nextPageStart":2}`)
			return
		}
		if r.URL.Query().Get("start") != "2" {
			t.Errorf("unexpected offset: %s", r.URL.RawQuery)
		}
		_, _ = io.WriteString(w, `{"values":[{"id":3,"fromRef":{"id":"refs/heads/feature","repository":{"slug":"bender","project":{"key":"GIT"}}},"toRef":{"id":"refs/heads/master"}}],"isLastPage":true}`)
	})
	link, err := client.EnsurePullRequest(context.Background(), bitbucket.Repo{ProjectKey: "GIT", Slug: "bender"}, "feature", "master", "title")
	if err != nil || !strings.HasSuffix(link, "/3") || gets != 2 {
		t.Fatalf("link=%q gets=%d err=%v", link, gets, err)
	}
}

func TestClient_EnsurePullRequest_Conflict(t *testing.T) {
	t.Parallel()
	for _, found := range []bool{true, false} {
		t.Run(map[bool]string{true: "concurrent creation", false: "unrelated conflict"}[found], func(t *testing.T) {
			posted := false
			client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posted = true
					w.WriteHeader(http.StatusConflict)
					return
				}
				if posted && found {
					_, _ = io.WriteString(w, `{"values":[{"id":9,"fromRef":{"id":"refs/heads/feature","repository":{"slug":"bender","project":{"key":"GIT"}}},"toRef":{"id":"refs/heads/master"}}],"isLastPage":true}`)
					return
				}
				_, _ = io.WriteString(w, `{"values":[],"isLastPage":true}`)
			})
			link, err := client.EnsurePullRequest(context.Background(), bitbucket.Repo{ProjectKey: "GIT", Slug: "bender"}, "feature", "master", "title")
			if found {
				if err != nil || !strings.HasSuffix(link, "/9") {
					t.Fatalf("link=%q err=%v", link, err)
				}
			} else if !errors.Is(err, bitbucket.ErrAlreadyExists) {
				t.Fatalf("unrelated conflict must fail: %v", err)
			}
		})
	}
}

func TestClient_EnsurePullRequest_LookupFailure(t *testing.T) {
	t.Parallel()
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Error("must not create after a failed lookup")
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	if _, err := client.EnsurePullRequest(context.Background(), bitbucket.Repo{ProjectKey: "GIT", Slug: "bender"}, "feature", "master", "title"); err == nil {
		t.Fatal("expected unauthorized lookup to fail")
	}
}

// repositoryJSON mirrors a real response from the instance, including the
// clone links in http-first order.
func repositoryJSON(slug string, archived bool) string {
	body := map[string]any{
		"slug":     slug,
		"name":     slug,
		"scmId":    "git",
		"state":    "AVAILABLE",
		"archived": archived,
		"project":  map[string]any{"key": "SEC"},
		"links": map[string]any{
			"clone": []map[string]string{
				{"href": "https://bitbucket.example.no/scm/sec/" + slug + ".git", "name": "http"},
				{"href": "ssh://git@bitbucket.example.no:7999/sec/" + slug + ".git", "name": "ssh"},
			},
		},
	}
	out, _ := json.Marshal(body)
	return string(out)
}

// Granting a user write access is how a personal ssh key gets push rights:
// Bitbucket refuses to register such a key as a repository access key.
func TestClient_AddUserPermission(t *testing.T) {
	t.Parallel()

	var gotMethod, gotPath, gotName, gotPermission string
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotName = r.URL.Query().Get("name")
		gotPermission = r.URL.Query().Get("permission")
		w.WriteHeader(http.StatusNoContent)
	})

	if err := client.AddUserPermission(context.Background(), bitbucket.Repo{ProjectKey: "SEC", Slug: "sealedsecrets-dev"}, "kts_builder", "REPO_WRITE"); err != nil {
		t.Fatalf("AddUserPermission() error = %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if want := "/rest/api/1.0/projects/SEC/repos/sealedsecrets-dev/permissions/users"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if gotName != "kts_builder" {
		t.Errorf("name = %q, want kts_builder", gotName)
	}
	if gotPermission != "REPO_WRITE" {
		t.Errorf("permission = %q, want REPO_WRITE", gotPermission)
	}
}

// A username needing escaping must survive as a query value rather than
// corrupting the request path.
func TestClient_AddUserPermission_EscapesName(t *testing.T) {
	t.Parallel()

	var gotName string
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotName = r.URL.Query().Get("name")
		w.WriteHeader(http.StatusNoContent)
	})

	if err := client.AddUserPermission(context.Background(), bitbucket.Repo{ProjectKey: "SEC", Slug: "repo"}, "first last&x=1", "REPO_WRITE"); err != nil {
		t.Fatalf("AddUserPermission() error = %v", err)
	}
	if gotName != "first last&x=1" {
		t.Errorf("name = %q, want %q", gotName, "first last&x=1")
	}
}

const testReaderKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDnylCPIwNdp4hLwjoqn70nR1TNR5H/03/RpfcHh3MAp argocd_gitreader@example.com"

// A standalone key, unlike a personal one, can be registered as a repository
// access key: that is how ArgoCD is given read-only access.
func TestClient_AddAccessKey(t *testing.T) {
	t.Parallel()

	var gotMethod, gotPath string
	var body struct {
		Key struct {
			Text string `json:"text"`
		} `json:"key"`
		Permission string `json:"permission"`
	}
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
	})

	if err := client.AddAccessKey(context.Background(), bitbucket.Repo{ProjectKey: "SEC", Slug: "sealedsecrets-dev"}, testReaderKey, "REPO_READ"); err != nil {
		t.Fatalf("AddAccessKey() error = %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if want := "/rest/keys/1.0/projects/SEC/repos/sealedsecrets-dev/ssh"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if body.Key.Text != testReaderKey {
		t.Errorf("key text = %q, want %q", body.Key.Text, testReaderKey)
	}
	if body.Permission != "REPO_READ" {
		t.Errorf("permission = %q, want REPO_READ", body.Permission)
	}
}

// Re-registering the same key on the same repository is how a retried
// provision converges, so that conflict is not an error. The envelope is the
// one a live Bitbucket 8 instance returns.
func TestClient_AddAccessKey_ToleratesDuplicate(t *testing.T) {
	t.Parallel()

	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"errors":[{"context":null,"message":"SSH key already provides access to this repository","exceptionName":"com.atlassian.bitbucket.ssh.DuplicateSshKeyException"}]}`)
	})

	if err := client.AddAccessKey(context.Background(), bitbucket.Repo{ProjectKey: "SEC", Slug: "repo"}, testReaderKey, "REPO_READ"); err != nil {
		t.Fatalf("AddAccessKey() error = %v, want nil for a duplicate key", err)
	}
}

// Bitbucket also answers 409 when the key belongs to a user account, which is
// a refusal rather than an idempotent repeat. Swallowing it once left
// repositories with no grant at all. Only DuplicateSshKeyException is
// tolerated, so any other exception name stands in for that case.
func TestClient_AddAccessKey_RejectsForeignConflict(t *testing.T) {
	t.Parallel()

	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"errors":[{"message":"This SSH key is already assigned to 'kts_builder'.","exceptionName":"com.atlassian.stash.ssh.api.SshKeyAlreadyInUseException"}]}`)
	})

	err := client.AddAccessKey(context.Background(), bitbucket.Repo{ProjectKey: "SEC", Slug: "repo"}, testReaderKey, "REPO_READ")
	if err == nil {
		t.Fatal("AddAccessKey() = nil, want error when the key belongs to an account")
	}
	if !strings.Contains(err.Error(), "kts_builder") {
		t.Errorf("error %q does not report why Bitbucket refused", err)
	}
}

func TestClient_CreateRepo(t *testing.T) {
	t.Parallel()

	var gotPath, gotAuth, gotBody string
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, repositoryJSON("sealedsecrets-new", false))
	})

	repo, err := client.CreateRepo(context.Background(), bitbucket.Repo{ProjectKey: "sec", Slug: "sealedsecrets-new"})
	if err != nil {
		t.Fatalf("CreateRepo() error = %v", err)
	}

	if want := "/rest/api/1.0/projects/sec/repos"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if want := "Bearer " + testToken; gotAuth != want {
		t.Errorf("authorization = %q, want %q", gotAuth, want)
	}
	if !strings.Contains(gotBody, `"sealedsecrets-new"`) || !strings.Contains(gotBody, `"git"`) {
		t.Errorf("request body = %s", gotBody)
	}
	if repo.Slug != "sealedsecrets-new" {
		t.Errorf("slug = %q, want sealedsecrets-new", repo.Slug)
	}
}

// The clone array order varies per repository on the real instance, so the ssh
// URL must be selected by name rather than position.
func TestRepository_SSHCloneURL(t *testing.T) {
	t.Parallel()

	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, repositoryJSON("sealedsecrets-dev", false))
	})

	repo, err := client.GetRepo(context.Background(), bitbucket.Repo{ProjectKey: "sec", Slug: "sealedsecrets-dev"})
	if err != nil {
		t.Fatalf("GetRepo() error = %v", err)
	}

	want := "ssh://git@bitbucket.example.no:7999/sec/sealedsecrets-dev.git"
	if got := repo.SSHCloneURL(); got != want {
		t.Errorf("SSHCloneURL() = %q, want %q", got, want)
	}
}

func TestClient_GetRepo_NotFound(t *testing.T) {
	t.Parallel()

	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"errors":[{"message":"Repository sec/nope does not exist.","exceptionName":"com.atlassian.bitbucket.repository.NoSuchRepositoryException"}]}`)
	})

	_, err := client.GetRepo(context.Background(), bitbucket.Repo{ProjectKey: "sec", Slug: "nope"})
	if !errors.Is(err, bitbucket.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

// A repeated provision must be able to tell "already there" from a real
// failure, so it can adopt the existing repository instead of aborting.
func TestClient_CreateRepo_AlreadyExists(t *testing.T) {
	t.Parallel()

	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"errors":[{"context":"name","message":"This repository URL is already taken.","exceptionName":null}]}`)
	})

	_, err := client.CreateRepo(context.Background(), bitbucket.Repo{ProjectKey: "sec", Slug: "sealedsecrets-dev"})
	if !errors.Is(err, bitbucket.ErrAlreadyExists) {
		t.Fatalf("error = %v, want ErrAlreadyExists", err)
	}
}

// Bitbucket reports failures in a nested errors array; the message is the only
// useful part and must reach the caller.
func TestClient_SurfacesRemoteMessage(t *testing.T) {
	t.Parallel()

	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"errors":[{"message":"The repository name is invalid.","exceptionName":null}]}`)
	})

	_, err := client.CreateRepo(context.Background(), bitbucket.Repo{ProjectKey: "sec", Slug: "bad name"})
	if err == nil {
		t.Fatal("invalid name was accepted")
	}
	if !strings.Contains(err.Error(), "The repository name is invalid.") {
		t.Errorf("error = %v, want the remote message", err)
	}
}

// The token authorises repository creation across the project; it must never
// reach a log line or an error string.
func TestClient_ErrorsDoNotLeakToken(t *testing.T) {
	t.Parallel()

	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"errors":[{"message":"boom"}]}`)
	})

	_, err := client.CreateRepo(context.Background(), bitbucket.Repo{ProjectKey: "sec", Slug: "x"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Errorf("error leaks the token: %v", err)
	}
}

func TestNew_RejectsUnusableURL(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"", "not-a-url", "/rest/api"} {
		if _, err := bitbucket.New(raw, testToken); err == nil {
			t.Errorf("New(%q) was accepted", raw)
		}
	}
}
