package main

import (
	"net/http"
	"testing"
)

// The listener is reachable from the wider network, so every stage of a
// connection needs a deadline; a missing one is a free denial of service.
func TestNewHTTPServer_BoundsEveryStage(t *testing.T) {
	t.Parallel()

	srv := newHTTPServer(":8443", http.NotFoundHandler())

	for _, tc := range []struct {
		name  string
		value func() bool
	}{
		{"ReadHeaderTimeout", func() bool { return srv.ReadHeaderTimeout > 0 }},
		{"ReadTimeout", func() bool { return srv.ReadTimeout > 0 }},
		{"WriteTimeout", func() bool { return srv.WriteTimeout > 0 }},
		{"IdleTimeout", func() bool { return srv.IdleTimeout > 0 }},
	} {
		if !tc.value() {
			t.Errorf("%s is unset", tc.name)
		}
	}

	// Provisioning talks to Vault, the API server and git before it replies.
	if srv.WriteTimeout <= srv.ReadTimeout {
		t.Error("WriteTimeout must leave room for provisioning to finish")
	}
}
