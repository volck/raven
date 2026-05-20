package auth

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// ClientCredentials handles OIDC client credentials flow for fetching tokens.
type ClientCredentials struct {
	config clientcredentials.Config
}

// NewClientCredentials creates a ClientCredentials configured for the given
// token endpoint, client ID, client secret, and scopes.
func NewClientCredentials(tokenURL string, clientID string, clientSecret string, scopes []string) *ClientCredentials {
	return &ClientCredentials{
		config: clientcredentials.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			TokenURL:     tokenURL,
			Scopes:       scopes,
		},
	}
}

// Token fetches an access token using the client credentials flow.
func (cc *ClientCredentials) Token(ctx context.Context) (string, error) {
	tokenSource := cc.config.TokenSource(ctx)
	token, err := tokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("failed to fetch token: %w", err)
	}
	return token.AccessToken, nil
}

// HTTPClient returns an *http.Client that automatically attaches the Bearer
// token to outbound requests, refreshing as needed.
func (cc *ClientCredentials) HTTPClient(ctx context.Context) *http.Client {
	return oauth2.NewClient(ctx, cc.config.TokenSource(ctx))
}
