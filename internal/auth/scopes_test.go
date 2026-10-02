package auth

import (
	"context"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
)

func scopeToken(t *testing.T, key *rsa.PrivateKey, issuer string, extra map[string]interface{}) string {
	t.Helper()

	now := time.Now()
	claims := map[string]interface{}{
		"iss": issuer,
		"aud": "raven-api",
		"sub": "provisioner",
		"exp": jwt.NewNumericDate(now.Add(1 * time.Hour)),
		"iat": jwt.NewNumericDate(now),
	}
	for k, v := range extra {
		claims[k] = v
	}
	return signToken(t, key, claims)
}

func TestTokenVerifier_ExtractsScopes(t *testing.T) {
	srv, key := testOIDCProvider(t)
	defer srv.Close()

	verifier, err := NewTokenVerifier(context.Background(), srv.URL, "raven-api")
	if err != nil {
		t.Fatal(err)
	}

	token := scopeToken(t, key, srv.URL, map[string]interface{}{
		"scope": "openid profile raven:provision",
	})

	claims, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !claims.HasScope("raven:provision") {
		t.Errorf("scopes = %v, want raven:provision", claims.Scopes)
	}
	if !claims.HasScope("openid") {
		t.Errorf("scopes = %v, want openid", claims.Scopes)
	}
}

// Irregular spacing is legal in a space-delimited claim and must not produce
// empty entries, which would otherwise make HasScope("") match.
func TestTokenVerifier_ToleratesIrregularSpacing(t *testing.T) {
	srv, key := testOIDCProvider(t)
	defer srv.Close()

	verifier, err := NewTokenVerifier(context.Background(), srv.URL, "raven-api")
	if err != nil {
		t.Fatal(err)
	}

	token := scopeToken(t, key, srv.URL, map[string]interface{}{
		"scope": "  openid   raven:provision  ",
	})

	claims, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if len(claims.Scopes) != 2 {
		t.Fatalf("scopes = %v, want exactly 2", claims.Scopes)
	}
	if !claims.HasScope("raven:provision") {
		t.Errorf("scopes = %v, want raven:provision", claims.Scopes)
	}
}

// A broader scope must not satisfy a narrower one by prefix.
func TestTokenVerifier_ScopeMatchIsExact(t *testing.T) {
	srv, key := testOIDCProvider(t)
	defer srv.Close()

	verifier, err := NewTokenVerifier(context.Background(), srv.URL, "raven-api")
	if err != nil {
		t.Fatal(err)
	}

	token := scopeToken(t, key, srv.URL, map[string]interface{}{
		"scope": "raven:provision:readonly",
	})

	claims, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if claims.HasScope("raven:provision") {
		t.Errorf("a longer scope matched by prefix: %v", claims.Scopes)
	}
}

// A token carrying no scope claim is still a valid token; it simply grants
// nothing.
func TestTokenVerifier_NoScopeIsNotAnError(t *testing.T) {
	srv, key := testOIDCProvider(t)
	defer srv.Close()

	verifier, err := NewTokenVerifier(context.Background(), srv.URL, "raven-api")
	if err != nil {
		t.Fatal(err)
	}

	claims, err := verifier.Verify(context.Background(), scopeToken(t, key, srv.URL, nil))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if len(claims.Scopes) != 0 {
		t.Errorf("scopes = %v, want none", claims.Scopes)
	}
	if claims.HasScope("") {
		t.Error("the empty scope must never match")
	}
}
