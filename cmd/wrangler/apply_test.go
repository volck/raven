package main

import (
	"context"
	"testing"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/volck/raven/internal/provision"
)

func applyAll(t *testing.T, spec provision.RavenSpec, defaults ravenDefaults) *clusterApplier {
	t.Helper()

	applier := newClusterApplier(k8sfake.NewSimpleClientset(preflightObjects()...), routeClient(t), defaults)
	if err := applier.Apply(context.Background(), spec, testToken); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	return applier
}

// Apply only ever creates, so a forced request that did not delete first would
// leave the old workload running and report success.
func TestClusterApplier_Delete(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	spec := wranglerSpec()
	applier := applyAll(t, spec, testDefaults())

	if err := applier.Delete(ctx, spec); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	if _, err := applier.clientset.AppsV1().Deployments(spec.Namespace).Get(ctx, spec.Name, metav1.GetOptions{}); !k8serrors.IsNotFound(err) {
		t.Errorf("deployment survived Delete: %v", err)
	}
	if _, err := applier.clientset.CoreV1().Services(spec.Namespace).Get(ctx, spec.Name, metav1.GetOptions{}); !k8serrors.IsNotFound(err) {
		t.Errorf("service survived Delete: %v", err)
	}
	if _, err := applier.dynamic.Resource(routeGVR).Namespace(spec.Namespace).Get(ctx, spec.Name, metav1.GetOptions{}); !k8serrors.IsNotFound(err) {
		t.Errorf("route survived Delete: %v", err)
	}

	// The token Secret stays, so the recreated raven reuses the credential
	// rather than stranding the old one in Vault.
	if exists, err := applier.TokenSecretExists(ctx, spec); err != nil || !exists {
		t.Errorf("TokenSecretExists() = %v, %v; want true, nil", exists, err)
	}

	if err := applier.Delete(ctx, spec); err != nil {
		t.Errorf("second Delete() error = %v", err)
	}
}

// A retried request must not fail on objects a previous attempt created.
func TestClusterApplier_Apply_Idempotent(t *testing.T) {
	t.Parallel()

	spec := wranglerSpec()
	applier := applyAll(t, spec, testDefaults())

	if err := applier.Apply(context.Background(), spec, testToken); err != nil {
		t.Fatalf("second Apply() error = %v", err)
	}

	ctx := context.Background()
	deployments, err := applier.clientset.AppsV1().Deployments(spec.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list deployments: %v", err)
	}
	if got := len(deployments.Items); got != 1 {
		t.Errorf("got %d deployments, want 1", got)
	}
	services, err := applier.clientset.CoreV1().Services(spec.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list services: %v", err)
	}
	if got := len(services.Items); got != 1 {
		t.Errorf("got %d services, want 1", got)
	}
	routes, err := applier.dynamic.Resource(routeGVR).Namespace(spec.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list routes: %v", err)
	}
	if got := len(routes.Items); got != 1 {
		t.Errorf("got %d routes, want 1", got)
	}
	if exists, err := applier.TokenSecretExists(ctx, spec); err != nil || !exists {
		t.Errorf("token secret missing after re-apply: exists=%v err=%v", exists, err)
	}
}

// The host is derived once so the Route and the discovery annotation agree.
func TestClusterApplier_Apply_DerivesRouteHost(t *testing.T) {
	t.Parallel()

	spec := wranglerSpec()
	spec.RouteHost = ""

	defaults := testDefaults()
	defaults.ClusterDomain = "apps.example.com"

	applier := applyAll(t, spec, defaults)
	ctx := context.Background()

	want := spec.DefaultRouteHost(defaults.ClusterDomain)
	if want == "" {
		t.Fatal("test setup: expected a derived host")
	}

	route, err := applier.dynamic.Resource(routeGVR).Namespace(spec.Namespace).Get(ctx, spec.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get route: %v", err)
	}
	got, found, err := unstructured.NestedString(route.Object, "spec", "host")
	if err != nil || !found {
		t.Fatalf("spec.host not set: %v", err)
	}
	if got != want {
		t.Errorf("route host = %q, want %q", got, want)
	}

	deploy, err := applier.clientset.AppsV1().Deployments(spec.Namespace).Get(ctx, spec.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	if got, want := deploy.Annotations[provision.AnnoTarget], "https://"+want; got != want {
		t.Errorf("target annotation = %q, want %q", got, want)
	}
}

// Without a host the annotation would otherwise read "https://".
func TestClusterApplier_Apply_OmitsTargetWithoutHost(t *testing.T) {
	t.Parallel()

	spec := wranglerSpec()
	spec.RouteHost = ""

	applier := applyAll(t, spec, testDefaults())

	deploy, err := applier.clientset.AppsV1().Deployments(spec.Namespace).Get(context.Background(), spec.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	if got, ok := deploy.Annotations[provision.AnnoTarget]; ok {
		t.Errorf("target annotation = %q, want it absent", got)
	}
}
