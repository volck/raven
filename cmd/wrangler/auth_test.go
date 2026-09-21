package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/volck/raven/internal/auth"
)

type fakeVerifier struct {
	subject string
	scopes  []string
	err     error
}

func (f fakeVerifier) Verify(_ context.Context, rawToken string) (*auth.Claims, error) {
	if f.err != nil {
		return nil, f.err
	}
	if rawToken == "" {
		return nil, errors.New("empty token")
	}
	return &auth.Claims{Subject: f.subject, Issuer: "https://issuer.example.com", Scopes: f.scopes}, nil
}

// spyHandler records whether the request reached the protected handler.
type spyHandler struct {
	called bool
	claims *auth.Claims
}

func (s *spyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.called = true
	s.claims, _ = claimsFrom(r.Context())
	w.WriteHeader(http.StatusOK)
}

func guard(t *testing.T, v tokenVerifier, requiredScope string, header string) (*httptest.ResponseRecorder, *spyHandler) {
	t.Helper()

	spy := &spyHandler{}
	handler := authMiddleware(v, requiredScope)(spy)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ravens", nil)
	if header != "" {
		req.Header.Set("Authorization", header)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec, spy
}

func TestAuthMiddleware_Rejects(t *testing.T) {
	t.Parallel()

	const required = "raven:provision"

	tests := []struct {
		name     string
		verifier tokenVerifier
		header   string
		want     int
	}{
		{
			name:     "no authorization header",
			verifier: fakeVerifier{scopes: []string{required}},
			want:     http.StatusUnauthorized,
		},
		{
			name:     "not a bearer token",
			verifier: fakeVerifier{scopes: []string{required}},
			header:   "Basic c29tZTp0aGluZw==",
			want:     http.StatusUnauthorized,
		},
		{
			name:     "token fails verification",
			verifier: fakeVerifier{err: errors.New("signature mismatch")},
			header:   "Bearer bad-token",
			want:     http.StatusUnauthorized,
		},
		{
			name:     "valid token without the scope",
			verifier: fakeVerifier{subject: "someone-else", scopes: []string{"raven:read"}},
			header:   "Bearer good-token",
			want:     http.StatusForbidden,
		},
		{
			name:     "valid token carrying no scopes",
			verifier: fakeVerifier{subject: "someone-else"},
			header:   "Bearer good-token",
			want:     http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec, spy := guard(t, tc.verifier, required, tc.header)

			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d", rec.Code, tc.want)
			}
			if spy.called {
				t.Error("request reached the handler despite being rejected")
			}
		})
	}
}

func TestAuthMiddleware_AllowsScopeHolder(t *testing.T) {
	t.Parallel()

	verifier := fakeVerifier{subject: "provisioner", scopes: []string{"raven:read", "raven:provision"}}
	rec, spy := guard(t, verifier, "raven:provision", "Bearer good-token")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !spy.called {
		t.Fatal("request did not reach the handler")
	}
	if spy.claims == nil {
		t.Fatal("claims were not placed in the request context")
	}
	if spy.claims.Subject != "provisioner" {
		t.Errorf("subject = %q, want %q", spy.claims.Subject, "provisioner")
	}
}

// An unset scope must deny everyone rather than admit everyone.
func TestAuthMiddleware_EmptyScopeDeniesAll(t *testing.T) {
	t.Parallel()

	verifier := fakeVerifier{subject: "provisioner", scopes: []string{"raven:provision", ""}}
	rec, spy := guard(t, verifier, "", "Bearer good-token")

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if spy.called {
		t.Error("request reached the handler with no scope configured")
	}
}

// Rejection messages are echoed to the caller and must not repeat the token
// or the verifier's internal complaint.
func TestAuthMiddleware_ErrorBodyLeaksNothing(t *testing.T) {
	t.Parallel()

	rec, _ := guard(t, fakeVerifier{err: errors.New("signature mismatch")}, "raven:provision", "Bearer super-secret-token")

	body := rec.Body.String()
	for _, leak := range []string{"super-secret-token", "signature mismatch"} {
		if strings.Contains(body, leak) {
			t.Errorf("response body leaks %q: %s", leak, body)
		}
	}
}
