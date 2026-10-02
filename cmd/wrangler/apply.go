package main

import (
	"context"
	"fmt"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/volck/raven/internal/provision"
)

// Apply creates the four cluster objects a raven needs. The token Secret goes
// first so the Deployment never references a secret that is not there yet.
func (a *clusterApplier) Apply(ctx context.Context, spec provision.RavenSpec, token string) error {
	spec.RouteHost = spec.DefaultRouteHost(a.defaults.ClusterDomain)

	steps := []struct {
		name string
		run  func() error
	}{
		{"token secret", func() error { return a.ApplyTokenSecret(ctx, spec, token) }},
		{"deployment", func() error { return a.ApplyDeployment(ctx, spec) }},
		{"service", func() error { return a.ApplyService(ctx, spec) }},
		{"route", func() error { return a.ApplyRoute(ctx, spec) }},
	}
	for _, step := range steps {
		if err := step.run(); err != nil {
			return fmt.Errorf("apply %s: %w", step.name, err)
		}
	}
	return nil
}

// Delete removes the objects Apply creates, except the token Secret: keeping
// the credential lets the recreated raven reuse it instead of stranding the
// old one in Vault.
func (a *clusterApplier) Delete(ctx context.Context, spec provision.RavenSpec) error {
	background := metav1.DeleteOptions{PropagationPolicy: ptr.To(metav1.DeletePropagationBackground)}

	steps := []struct {
		name string
		run  func() error
	}{
		{"route", func() error {
			return a.dynamic.Resource(routeGVR).Namespace(spec.Namespace).Delete(ctx, spec.Name, background)
		}},
		{"service", func() error {
			return a.clientset.CoreV1().Services(spec.Namespace).Delete(ctx, spec.Name, background)
		}},
		{"deployment", func() error {
			return a.clientset.AppsV1().Deployments(spec.Namespace).Delete(ctx, spec.Name, background)
		}},
	}
	for _, step := range steps {
		if err := step.run(); err != nil && !k8serrors.IsNotFound(err) {
			return fmt.Errorf("delete %s %s: %w", step.name, spec.Name, err)
		}
	}
	return nil
}
