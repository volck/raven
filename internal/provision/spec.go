// Package provision renders and publishes the artefacts needed to stand up a
// new raven: the spec that describes it, the ArgoCD Application that later
// syncs its sealed secrets, and the git branch that carries that Application.
package provision

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

// RavenSpec describes a raven to provision. It is a plain data transfer
// object: callers construct it directly and call Validate.
type RavenSpec struct {
	Name         string
	Namespace    string
	SecretEngine string
	DestEnv      string
	RepoURL      string
	Image        string
	RouteHost    string

	// AWSWriteback mirrors raven's AWS_WRITEBACK flag, which defaults to off.
	AWSWriteback bool
}

// Validate reports whether the spec is well formed. It checks field shape
// only; existence of the namespace, engine or image is not verified here.
func (s RavenSpec) Validate() error {
	if errs := validation.IsDNS1123Subdomain(s.Name); s.Name == "" || len(errs) > 0 {
		return fmt.Errorf("name %q: must be a DNS-1123 subdomain", s.Name)
	}
	if errs := validation.IsDNS1123Label(s.Namespace); s.Namespace == "" || len(errs) > 0 {
		return fmt.Errorf("namespace %q: must be a DNS-1123 label", s.Namespace)
	}
	if errs := validation.IsDNS1123Label(s.SecretEngine); s.SecretEngine == "" || len(errs) > 0 {
		return fmt.Errorf("secretEngine %q: must be a DNS-1123 label", s.SecretEngine)
	}
	if errs := validation.IsDNS1123Label(s.DestEnv); s.DestEnv == "" || len(errs) > 0 {
		return fmt.Errorf("destEnv %q: must be a DNS-1123 label", s.DestEnv)
	}
	if s.RepoURL == "" || strings.ContainsAny(s.RepoURL, " \t\n") {
		return fmt.Errorf("repoURL %q: must be a non-empty URL without whitespace", s.RepoURL)
	}
	if s.Image == "" || strings.ContainsAny(s.Image, " \t\n") {
		return fmt.Errorf("image %q: must be a non-empty reference without whitespace", s.Image)
	}
	if s.RouteHost != "" {
		if errs := validation.IsDNS1123Subdomain(s.RouteHost); len(errs) > 0 {
			return fmt.Errorf("routeHost %q: must be a DNS-1123 subdomain", s.RouteHost)
		}
	}
	return nil
}

// DefaultRouteHost returns the explicit RouteHost when set, otherwise it
// derives one from the name, namespace and clusterDomain. An empty
// clusterDomain yields an empty host, leaving the router to assign one.
func (s RavenSpec) DefaultRouteHost(clusterDomain string) string {
	if s.RouteHost != "" {
		return s.RouteHost
	}
	if clusterDomain == "" {
		return ""
	}
	return fmt.Sprintf("%s-%s.%s", s.Name, s.Namespace, clusterDomain)
}

// SealedSecretsPath is the directory in RepoURL that raven writes sealed
// secrets to, and therefore the only path an Application may sync. Derived
// rather than configured so it cannot drift from what raven does.
func (s RavenSpec) SealedSecretsPath() string {
	return fmt.Sprintf("declarative/%s/sealedsecrets", s.DestEnv)
}
