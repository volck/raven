package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Claims represents the verified JWT claims extracted from a token.
type Claims struct {
	Subject string
	Issuer  string
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

// Verify validates a raw JWT token string and returns the extracted claims.
func (tv *TokenVerifier) Verify(ctx context.Context, rawToken string) (*Claims, error) {
	idToken, err := tv.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	return &Claims{
		Subject: idToken.Subject,
		Issuer:  idToken.Issuer,
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
