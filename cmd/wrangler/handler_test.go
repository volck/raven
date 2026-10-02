package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/volck/raven/internal/auth"
	"github.com/volck/raven/internal/provision"
)

func testLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func testClaims() *auth.Claims {
	return &auth.Claims{Subject: "system:serviceaccount:ci:provisioner", Issuer: "https://issuer.example.com"}
}

type fakeVault struct {
	mu        sync.Mutex
	engines   []string
	policies  []string
	tokens    int
	revoked   []string
	failOn    string
	revokeErr error
}

func (f *fakeVault) EnsureEngine(_ context.Context, engine string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOn == "engine" {
		return errors.New("mount refused")
	}
	f.engines = append(f.engines, engine)
	return nil
}

func (f *fakeVault) EnsurePolicy(_ context.Context, name, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOn == "policy" {
		return errors.New("policy refused")
	}
	f.policies = append(f.policies, name)
	return nil
}

func (f *fakeVault) CreateToken(_ context.Context, _ string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOn == "token" {
		return "", errors.New("ttl capped")
	}
	f.tokens++
	return testToken, nil
}

func (f *fakeVault) tokenCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokens
}

func (f *fakeVault) RevokeToken(_ context.Context, token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revokeErr != nil {
		return f.revokeErr
	}
	f.revoked = append(f.revoked, token)
	return nil
}

func (f *fakeVault) revokedTokens() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.revoked...)
}

type fakeApplier struct {
	mu                 sync.Mutex
	preflightErr       error
	applyErr           error
	deleteErr          error
	tokenExists        bool
	applyCreatesSecret bool
	applied            int
	deleted            int
	forced             bool
	appliedToken       string
	preflightCalls     int
}

func (f *fakeApplier) Preflight(_ context.Context, _ provision.RavenSpec, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.preflightCalls++
	f.forced = force
	return f.preflightErr
}

func (f *fakeApplier) Delete(_ context.Context, _ provision.RavenSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleted++
	return nil
}

func (f *fakeApplier) TokenSecretExists(_ context.Context, _ provision.RavenSpec) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokenExists, nil
}

func (f *fakeApplier) Apply(_ context.Context, _ provision.RavenSpec, token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.applyErr != nil {
		if f.applyCreatesSecret {
			f.tokenExists = true
		}
		return f.applyErr
	}
	f.applied++
	f.appliedToken = token
	return nil
}

type fakePublisher struct {
	mu     sync.Mutex
	calls  int
	err    error
	branch string
}

func (f *fakePublisher) Publish(ctx context.Context, spec provision.RavenSpec, _ []provision.File) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	f.calls++
	if f.err != nil {
		return "", f.err
	}
	f.branch = provision.BranchName(spec)
	return f.branch, nil
}

func (f *fakePublisher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

const testImage = "registry.example.com/ssg/raven@sha256:configured"

const testNamespace = "ssg"

func validBody() string {
	return `{
		"name": "ssg-dev",
		"secretEngine": "kv",
		"destEnv": "dev",
		"repoURL": "ssh://git@bitbucket.example.com:7999/sec/sealedsecrets-dev.git",
		"routeHost": "ssg-dev-ssg.apps.example.com"
	}`
}

func newTestDeps() (createDeps, *fakeVault, *fakeApplier, *fakePublisher) {
	vault := &fakeVault{}
	applier := &fakeApplier{}
	publisher := &fakePublisher{}

	return createDeps{
		vault:     vault,
		applier:   applier,
		publisher: publisher,
		image:     testImage,
		namespace: testNamespace,
		appConfig: provision.ApplicationConfig{
			TargetRevision: "master",
			DestServer:     "https://kubernetes.default.svc",
		},
	}, vault, applier, publisher
}

func post(t *testing.T, deps createDeps, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ravens", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleCreateRaven(deps).ServeHTTP(rec, req)
	return rec
}

func TestHandleCreateRaven_Accepts(t *testing.T) {
	t.Parallel()

	deps, vault, applier, publisher := newTestDeps()
	rec := post(t, deps, validBody())

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body)
	}

	var got struct {
		Branch    string `json:"branch"`
		Engine    string `json:"engine"`
		Namespace string `json:"namespace"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Branch != "raven/create-ssg-dev" {
		t.Errorf("branch = %q", got.Branch)
	}
	if got.Engine != "kv" {
		t.Errorf("engine = %q", got.Engine)
	}
	if got.Namespace != "ssg" {
		t.Errorf("namespace = %q", got.Namespace)
	}

	if vault.tokenCount() != 1 {
		t.Errorf("minted %d tokens, want 1", vault.tokenCount())
	}
	if applier.applied != 1 {
		t.Errorf("applied %d times, want 1", applier.applied)
	}
	if publisher.callCount() != 1 {
		t.Errorf("published %d times, want 1", publisher.callCount())
	}
}

// The image is wrangler's decision, not the caller's.
func TestHandleCreateRaven_UsesConfiguredImage(t *testing.T) {
	t.Parallel()

	deps, _, _, _ := newTestDeps()
	spy := &specSpy{}
	deps.applier = spy

	if rec := post(t, deps, validBody()); rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body)
	}
	if spy.spec.Image != testImage {
		t.Errorf("image = %q, want %q", spy.spec.Image, testImage)
	}
}

// The namespace is wrangler's decision too: it holds RBAC in exactly one, so
// the field has only ever had one legal value.
func TestHandleCreateRaven_UsesConfiguredNamespace(t *testing.T) {
	t.Parallel()

	deps, _, _, _ := newTestDeps()
	spy := &specSpy{}
	deps.applier = spy

	if rec := post(t, deps, validBody()); rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body)
	}
	if spy.spec.Namespace != testNamespace {
		t.Errorf("namespace = %q, want %q", spy.spec.Namespace, testNamespace)
	}
}

func TestHandleCreateRaven_RejectsCallerSuppliedNamespace(t *testing.T) {
	t.Parallel()

	deps, _, _, publisher := newTestDeps()
	body := `{"name":"ssg-dev","namespace":"kube-system","secretEngine":"kv","destEnv":"dev",
		"repoURL":"ssh://git@example.com/r.git"}`

	if rec := post(t, deps, body); rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if publisher.callCount() != 0 {
		t.Error("published despite rejecting the request")
	}
}

func TestHandleCreateRaven_RejectsCallerSuppliedImage(t *testing.T) {
	t.Parallel()

	deps, _, _, publisher := newTestDeps()
	body := `{"name":"ssg-dev","secretEngine":"kv","destEnv":"dev",
		"repoURL":"ssh://git@example.com/r.git","image":"evil.example.com/backdoor:latest"}`

	rec := post(t, deps, body)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if publisher.callCount() != 0 {
		t.Error("published despite rejecting the request")
	}
}

func TestHandleCreateRaven_BadRequests(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{"malformed json", `{"name": "ssg-dev"`},
		{"empty body", ``},
		{"invalid name", `{"name":"Not A Name","secretEngine":"kv","destEnv":"dev","repoURL":"ssh://git@example.com/r.git"}`},
		{"missing repo url", `{"name":"ssg-dev","secretEngine":"kv","destEnv":"dev"}`},
		{"unknown field", `{"name":"ssg-dev","secretEngine":"kv","destEnv":"dev","repoURL":"ssh://git@example.com/r.git","admin":true}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			deps, vault, _, publisher := newTestDeps()
			rec := post(t, deps, tc.body)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
			if vault.tokenCount() != 0 {
				t.Error("minted a token for an invalid request")
			}
			if publisher.callCount() != 0 {
				t.Error("published an invalid request")
			}
		})
	}
}

func TestHandleCreateRaven_RejectsOversizedBody(t *testing.T) {
	t.Parallel()

	deps, _, _, _ := newTestDeps()
	body := `{"name":"ssg-dev","junk":"` + strings.Repeat("a", 2<<20) + `"}`

	if rec := post(t, deps, body); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
}

func TestHandleCreateRaven_RejectsWrongMethod(t *testing.T) {
	t.Parallel()

	deps, _, _, _ := newTestDeps()

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/api/v1/ravens", strings.NewReader(validBody()))
		rec := httptest.NewRecorder()
		handleCreateRaven(deps).ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 405", method, rec.Code)
		}
	}
}

// A prerequisite the operator must fix is the caller's problem, not a crash.
func TestHandleCreateRaven_PreflightFailureStopsBeforeVault(t *testing.T) {
	t.Parallel()

	deps, vault, applier, publisher := newTestDeps()
	applier.preflightErr = errors.New("secret \"ssc\" not found in namespace \"ssg\"")

	rec := post(t, deps, validBody())

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
	if vault.tokenCount() != 0 {
		t.Error("minted a token before prerequisites were satisfied")
	}
	if publisher.callCount() != 0 {
		t.Error("published despite failed preflight")
	}
}

// A retry must not leave a second long-lived token behind.
func TestHandleCreateRaven_RetryMintsNoSecondToken(t *testing.T) {
	t.Parallel()

	deps, vault, applier, _ := newTestDeps()
	applier.tokenExists = true

	if rec := post(t, deps, validBody()); rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body)
	}
	if vault.tokenCount() != 0 {
		t.Errorf("minted %d tokens on retry, want 0", vault.tokenCount())
	}
}

func TestHandleCreateRaven_ClusterFailureDoesNotPublish(t *testing.T) {
	t.Parallel()

	deps, _, applier, publisher := newTestDeps()
	applier.applyErr = errors.New("route admission webhook rejected")

	rec := post(t, deps, validBody())

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(strings.ToLower(rec.Body.String()), "cluster") {
		t.Errorf("body does not identify the failing stage: %s", rec.Body)
	}
	if publisher.callCount() != 0 {
		t.Error("published a branch for a raven that was never created")
	}
}

func TestHandleCreateRaven_VaultFailureDoesNotPublish(t *testing.T) {
	t.Parallel()

	deps, vault, _, publisher := newTestDeps()
	vault.failOn = "token"

	rec := post(t, deps, validBody())

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if publisher.callCount() != 0 {
		t.Error("published despite the vault step failing")
	}
}

// The minted token must never reach the response or the logs.
func TestHandleCreateRaven_NeverEchoesToken(t *testing.T) {
	t.Parallel()

	deps, _, _, _ := newTestDeps()
	var logs strings.Builder
	deps.logger = testLogger(&logs)

	rec := post(t, deps, validBody())

	if strings.Contains(rec.Body.String(), testToken) {
		t.Errorf("response echoes the vault token: %s", rec.Body)
	}
	if strings.Contains(logs.String(), testToken) {
		t.Errorf("logs contain the vault token: %s", logs.String())
	}
}

func TestHandleCreateRaven_AuditsTheRequest(t *testing.T) {
	t.Parallel()

	deps, _, _, _ := newTestDeps()
	var logs strings.Builder
	deps.logger = testLogger(&logs)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ravens", strings.NewReader(validBody()))
	req = req.WithContext(context.WithValue(req.Context(), claimsKey, testClaims()))
	rec := httptest.NewRecorder()
	handleCreateRaven(deps).ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body)
	}
	for _, want := range []string{"system:serviceaccount:ci:provisioner", "ssg-dev", "raven/create-ssg-dev", "kv", "ssg"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("audit log missing %q: %s", want, logs.String())
		}
	}
}

// A caller that gives up must not leave a branch open for approval.
func TestHandleCreateRaven_CancelledRequestDoesNotPublish(t *testing.T) {
	t.Parallel()

	deps, _, _, publisher := newTestDeps()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ravens", strings.NewReader(validBody())).WithContext(ctx)
	rec := httptest.NewRecorder()
	handleCreateRaven(deps).ServeHTTP(rec, req)

	if publisher.callCount() != 0 {
		t.Error("published despite the request being cancelled")
	}
	if rec.Code == http.StatusAccepted {
		t.Error("reported success for a cancelled request")
	}
}

// specSpy captures the spec the handler assembled.
type specSpy struct {
	fakeApplier
	spec provision.RavenSpec
}

func (s *specSpy) Apply(ctx context.Context, spec provision.RavenSpec, token string) error {
	s.spec = spec
	return s.fakeApplier.Apply(ctx, spec, token)
}
