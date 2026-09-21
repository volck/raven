package main

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/volck/raven/internal/provision"
)

// The fake dynamic client needs the list kind registered up front for any GVR
// it has no built-in scheme entry for.
func routeClient(t *testing.T) *dynamicfake.FakeDynamicClient {
	t.Helper()

	scheme := runtime.NewScheme()
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{routeGVR: "RouteList"},
	)
}

func applyRoute(t *testing.T, spec provision.RavenSpec) *unstructured.Unstructured {
	t.Helper()

	dyn := routeClient(t)
	applier := newClusterApplier(k8sfake.NewSimpleClientset(preflightObjects()...), dyn, testDefaults())

	if err := applier.ApplyRoute(context.Background(), spec); err != nil {
		t.Fatalf("ApplyRoute() error = %v", err)
	}
	route, err := dyn.Resource(routeGVR).Namespace(spec.Namespace).Get(context.Background(), spec.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get route: %v", err)
	}
	return route
}

func nestedString(t *testing.T, obj *unstructured.Unstructured, fields ...string) string {
	t.Helper()

	value, found, err := unstructured.NestedString(obj.Object, fields...)
	if err != nil || !found {
		t.Fatalf("field %v not found: %v", fields, err)
	}
	return value
}

func TestClusterApplier_ApplyRoute(t *testing.T) {
	t.Parallel()

	spec := wranglerSpec()
	route := applyRoute(t, spec)

	if got := route.GetAPIVersion(); got != "route.openshift.io/v1" {
		t.Errorf("apiVersion = %q", got)
	}
	if got := route.GetKind(); got != "Route" {
		t.Errorf("kind = %q", got)
	}
	if got := nestedString(t, route, "spec", "host"); got != spec.RouteHost {
		t.Errorf("host = %q, want %q", got, spec.RouteHost)
	}
	if got := route.GetLabels()[provision.LabelManagedBy]; got != provision.ManagedByWrangler {
		t.Errorf("route is not stamped as wrangler-managed: %v", route.GetLabels())
	}
}

// The Route must point at the Service the applier creates, by name.
func TestClusterApplier_ApplyRoute_TargetsService(t *testing.T) {
	t.Parallel()

	spec := wranglerSpec()
	route := applyRoute(t, spec)

	if got := nestedString(t, route, "spec", "to", "kind"); got != "Service" {
		t.Errorf("to.kind = %q, want Service", got)
	}
	if got := nestedString(t, route, "spec", "to", "name"); got != spec.Name {
		t.Errorf("to.name = %q, want %q", got, spec.Name)
	}
	port, found, err := unstructured.NestedInt64(route.Object, "spec", "port", "targetPort")
	if err != nil || !found {
		t.Fatalf("spec.port.targetPort not found: %v", err)
	}
	if port != ravenPort {
		t.Errorf("targetPort = %d, want %d", port, ravenPort)
	}
}

// Raven's route carries a Vault token in flight; plaintext must not be an option.
func TestClusterApplier_ApplyRoute_TLS(t *testing.T) {
	t.Parallel()

	route := applyRoute(t, wranglerSpec())

	if got := nestedString(t, route, "spec", "tls", "termination"); got != "edge" {
		t.Errorf("tls.termination = %q, want edge", got)
	}
	if got := nestedString(t, route, "spec", "tls", "insecureEdgeTerminationPolicy"); got != "Redirect" {
		t.Errorf("insecureEdgeTerminationPolicy = %q, want Redirect", got)
	}
}

// An empty host lets the router assign one; emitting "" would be rejected.
func TestClusterApplier_ApplyRoute_OmitsEmptyHost(t *testing.T) {
	t.Parallel()

	spec := wranglerSpec()
	spec.RouteHost = ""
	route := applyRoute(t, spec)

	if _, found, _ := unstructured.NestedString(route.Object, "spec", "host"); found {
		t.Error("spec.host is set despite the spec leaving it empty")
	}
}
