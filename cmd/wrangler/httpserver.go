package main

import (
	"net/http"
	"time"
)

// routeTimeout mirrors haproxy.router.openshift.io/timeout in
// deployments/wrangler.yaml. Both must move together.
const routeTimeout = 5 * time.Minute

// newHTTPServer bounds every stage of a connection. The listener is reachable
// from the wider network, so an unbounded read or idle socket is a cheap way
// to exhaust wrangler's goroutines and file descriptors.
func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		// Provisioning waits on Vault, the API server and a git push before
		// it can reply. Kept above routeTimeout so the router is the first
		// limit to bite: a WriteTimeout severs a connection whose work has
		// already succeeded, which surfaces as a bare 502.
		WriteTimeout: routeTimeout + time.Minute,
		IdleTimeout:  60 * time.Second,
	}
}
