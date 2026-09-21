package auth

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Claims represents the verified JWT claims extracted from a token.
type Claims struct {
	Subject string
	Issuer  string
	// Scopes holds the granted OAuth2 scopes, split from the space-delimited
	// scope claim.
	Scopes []string
}

// HasScope reports whether the token carries scope. Matching is exact, and the
// empty scope never matches.
func (c *Claims) HasScope(scope string) bool {
	if scope == "" {
		return false
	}
	return slices.Contains(c.Scopes, scope)
}

// TokenVerifier verifies OIDC JWT tokens using JWKS from the issuer.
type TokenVerifier struct {
	verifier *oidc.IDTokenVerifier
}

// NewTokenVerifier creates a TokenVerifier that validates tokens from the given
// OIDC issuer URL and expects the specified audience.
func NewTokenVerifier(ctx context.Context, issuerURL string, audience string) (*TokenVerifier, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: audience,
	})

	return &TokenVerifier{verifier: verifier}, nil
}

type scopeClaim struct {
	Scope string `json:"scope"`
}

// Verify validates a raw JWT token string and returns the extracted claims.
func (tv *TokenVerifier) Verify(ctx context.Context, rawToken string) (*Claims, error) {
	idToken, err := tv.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	// A token without a scope claim is valid; it just grants nothing.
	var sc scopeClaim
	_ = idToken.Claims(&sc)

	return &Claims{
		Subject: idToken.Subject,
		Issuer:  idToken.Issuer,
		Scopes:  strings.Fields(sc.Scope),
	}, nil
}

// ExtractBearerToken extracts the token from an "Authorization: Bearer <token>" header.
func ExtractBearerToken(authHeader string) (string, error) {
	if authHeader == "" {
		return "", fmt.Errorf("missing authorization header")
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return "", fmt.Errorf("invalid authorization header format")
	}
	return parts[1], nil
}
