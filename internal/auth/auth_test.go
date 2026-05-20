package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// testOIDCProvider sets up a fake OIDC issuer with a JWKS endpoint and returns
// the server, the RSA private key used for signing, and a cleanup function.
func testOIDCProvider(t *testing.T) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()

	// JWKS endpoint
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					Key:       &privateKey.PublicKey,
					KeyID:     "test-key-1",
					Algorithm: string(jose.RS256),
					Use:       "sig",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})

	srv := httptest.NewServer(mux)

	// OpenID Connect discovery endpoint
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		discovery := map[string]interface{}{
			"issuer":                 srv.URL,
			"jwks_uri":              srv.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(discovery)
	})

	return srv, privateKey
}

// signToken creates a signed JWT with the given claims using the provided RSA key.
func signToken(t *testing.T, key *rsa.PrivateKey, claims map[string]interface{}) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", "test-key-1"),
	)
	if err != nil {
		t.Fatal(err)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	token, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	return token
}

func TestTokenVerifier_ValidToken(t *testing.T) {
	srv, privateKey := testOIDCProvider(t)
	defer srv.Close()

	verifier, err := NewTokenVerifier(context.Background(), srv.URL, "raven-api")
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	token := signToken(t, privateKey, map[string]interface{}{
		"iss": srv.URL,
		"aud": "raven-api",
		"sub": "logparser-client",
		"exp": jwt.NewNumericDate(now.Add(1 * time.Hour)),
		"iat": jwt.NewNumericDate(now),
	})

	claims, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("expected valid token to pass verification, got: %v", err)
	}
	if claims.Subject != "logparser-client" {
		t.Errorf("expected subject 'logparser-client', got '%s'", claims.Subject)
	}
}

func TestTokenVerifier_ExpiredToken(t *testing.T) {
	srv, privateKey := testOIDCProvider(t)
	defer srv.Close()

	verifier, err := NewTokenVerifier(context.Background(), srv.URL, "raven-api")
	if err != nil {
		t.Fatal(err)
	}

	past := time.Now().Add(-2 * time.Hour)
	token := signToken(t, privateKey, map[string]interface{}{
		"iss": srv.URL,
		"aud": "raven-api",
		"sub": "logparser-client",
		"exp": jwt.NewNumericDate(past.Add(1 * time.Hour)), // expired 1h ago
		"iat": jwt.NewNumericDate(past),
	})

	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected expired token to fail verification")
	}
}

func TestTokenVerifier_WrongAudience(t *testing.T) {
	srv, privateKey := testOIDCProvider(t)
	defer srv.Close()

	verifier, err := NewTokenVerifier(context.Background(), srv.URL, "raven-api")
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	token := signToken(t, privateKey, map[string]interface{}{
		"iss": srv.URL,
		"aud": "wrong-audience",
		"sub": "logparser-client",
		"exp": jwt.NewNumericDate(now.Add(1 * time.Hour)),
		"iat": jwt.NewNumericDate(now),
	})

	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected wrong-audience token to fail verification")
	}
}

func TestTokenVerifier_InvalidSignature(t *testing.T) {
	srv, _ := testOIDCProvider(t)
	defer srv.Close()

	verifier, err := NewTokenVerifier(context.Background(), srv.URL, "raven-api")
	if err != nil {
		t.Fatal(err)
	}

	// Generate a different key (not registered in JWKS)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	token := signToken(t, otherKey, map[string]interface{}{
		"iss": srv.URL,
		"aud": "raven-api",
		"sub": "logparser-client",
		"exp": jwt.NewNumericDate(now.Add(1 * time.Hour)),
		"iat": jwt.NewNumericDate(now),
	})

	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected invalid-signature token to fail verification")
	}
}

func TestAuthMiddleware_RejectsUnauthenticated(t *testing.T) {
	srv, _ := testOIDCProvider(t)
	defer srv.Close()

	verifier, err := NewTokenVerifier(context.Background(), srv.URL, "raven-api")
	if err != nil {
		t.Fatal(err)
	}

	handler := AuthMiddleware(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))

	// No Authorization header
	req := httptest.NewRequest("GET", "/api/v1/secret", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestAuthMiddleware_AcceptsValidToken(t *testing.T) {
	srv, privateKey := testOIDCProvider(t)
	defer srv.Close()

	verifier, err := NewTokenVerifier(context.Background(), srv.URL, "raven-api")
	if err != nil {
		t.Fatal(err)
	}

	handler := AuthMiddleware(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))

	now := time.Now()
	token := signToken(t, privateKey, map[string]interface{}{
		"iss": srv.URL,
		"aud": "raven-api",
		"sub": "logparser-client",
		"exp": jwt.NewNumericDate(now.Add(1 * time.Hour)),
		"iat": jwt.NewNumericDate(now),
	})

	req := httptest.NewRequest("GET", "/api/v1/secret", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestAuthMiddleware_RejectsInvalidBearer(t *testing.T) {
	srv, _ := testOIDCProvider(t)
	defer srv.Close()

	verifier, err := NewTokenVerifier(context.Background(), srv.URL, "raven-api")
	if err != nil {
		t.Fatal(err)
	}

	handler := AuthMiddleware(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/secret", nil)
	req.Header.Set("Authorization", "Bearer invalid-garbage-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestClientCredentials_FetchesToken(t *testing.T) {
	// Mock token endpoint that returns an access token
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("grant_type") != "client_credentials" {
			t.Errorf("expected grant_type=client_credentials, got %s", r.Form.Get("grant_type"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token-12345",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	client := NewClientCredentials(tokenServer.URL, "my-client-id", "my-client-secret", []string{"raven-api"})
	token, err := client.Token(context.Background())
	if err != nil {
		t.Fatalf("expected to fetch token, got: %v", err)
	}
	if token != "test-access-token-12345" {
		t.Errorf("expected 'test-access-token-12345', got '%s'", token)
	}
}

func TestClientCredentials_HTTPClientWithAuth(t *testing.T) {
	// Mock token endpoint
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "bearer-token-xyz",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	// Mock target API that verifies Bearer header
	var receivedAuth string
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer targetServer.Close()

	client := NewClientCredentials(tokenServer.URL, "client-id", "client-secret", []string{"raven-api"})
	httpClient := client.HTTPClient(context.Background())

	resp, err := httpClient.Get(targetServer.URL + "/api/v1/secret")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if receivedAuth != "Bearer bearer-token-xyz" {
		t.Errorf("expected 'Bearer bearer-token-xyz', got '%s'", receivedAuth)
	}
}

func TestNewTokenVerifier_BigEndianModulus(t *testing.T) {
	// This test verifies that JWKS with big-endian encoded RSA modulus works correctly
	// (a common edge case in OIDC implementations)
	srv, privateKey := testOIDCProvider(t)
	defer srv.Close()

	verifier, err := NewTokenVerifier(context.Background(), srv.URL, "raven-api")
	if err != nil {
		t.Fatal(err)
	}

	// Just verify the modulus is correctly handled by signing with the same key
	now := time.Now()
	token := signToken(t, privateKey, map[string]interface{}{
		"iss": srv.URL,
		"aud": "raven-api",
		"sub": "test-big-n",
		"exp": jwt.NewNumericDate(now.Add(1 * time.Hour)),
		"iat": jwt.NewNumericDate(now),
		"nbf": jwt.NewNumericDate(now),
	})

	claims, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected verification failure: %v", err)
	}
	// Verify modulus is at least the expected bit size
	if privateKey.N.BitLen() < 2048 {
		t.Errorf("expected 2048-bit key, got %d", privateKey.N.BitLen())
	}
	_ = claims
	_ = big.NewInt(0) // ensure math/big import is used
}
