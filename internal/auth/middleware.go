package auth

import (
	"net/http"
)

// AuthMiddleware returns HTTP middleware that verifies OIDC Bearer tokens.
// Requests without a valid token receive a 401 Unauthorized response.
func AuthMiddleware(verifier *TokenVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := ExtractBearerToken(r.Header.Get("Authorization"))
			if err != nil {
				http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
				return
			}

			_, err = verifier.Verify(r.Context(), token)
			if err != nil {
				http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
