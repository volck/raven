package main

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/volck/raven/internal/auth"
)

// tokenVerifier is the slice of auth.TokenVerifier the gate needs, so tests
// can supply their own.
type tokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (*auth.Claims, error)
}

type contextKey int

const claimsKey contextKey = iota

func claimsFrom(ctx context.Context) (*auth.Claims, bool) {
	claims, ok := ctx.Value(claimsKey).(*auth.Claims)
	return claims, ok
}

// authMiddleware verifies the bearer token and admits only callers granted
// requiredScope. An empty scope admits nobody.
func authMiddleware(verifier tokenVerifier, requiredScope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := auth.ExtractBearerToken(r.Header.Get("Authorization"))
			if err != nil {
				denied(w, r, http.StatusUnauthorized, "", err)
				return
			}

			claims, err := verifier.Verify(r.Context(), token)
			if err != nil {
				denied(w, r, http.StatusUnauthorized, "", err)
				return
			}

			if !claims.HasScope(requiredScope) {
				denied(w, r, http.StatusForbidden, claims.Subject, nil)
				return
			}

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey, claims)))
		})
	}
}

// The reason is logged, never returned, so probing cannot map who has access.
func denied(w http.ResponseWriter, r *http.Request, status int, subject string, err error) {
	slog.WarnContext(r.Context(), "request denied",
		"status", status,
		"subject", subject,
		"path", r.URL.Path,
		"error", err,
	)
	http.Error(w, http.StatusText(status), status)
}
