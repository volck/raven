package main

import (
	"context"
	"fmt"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/volck/raven/internal/provision"
)

// OpenShift's Route types are not vendored, so the object is built untyped.
var routeGVR = schema.GroupVersionResource{
	Group:    "route.openshift.io",
	Version:  "v1",
	Resource: "routes",
}

func (a *clusterApplier) ApplyRoute(ctx context.Context, spec provision.RavenSpec) error {
	meta := objectMeta(spec, spec.Name)

	routeSpec := map[string]any{
		"to": map[string]any{
			"kind":   "Service",
			"name":   spec.Name,
			"weight": int64(100),
		},
		"port": map[string]any{
			"targetPort": int64(ravenPort),
		},
		"tls": map[string]any{
			"termination":                   "edge",
			"insecureEdgeTerminationPolicy": "Redirect",
		},
		"wildcardPolicy": "None",
	}
	if spec.RouteHost != "" {
		routeSpec["host"] = spec.RouteHost
	}

	route := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "route.openshift.io/v1",
		"kind":       "Route",
		"metadata": map[string]any{
			"name":        meta.Name,
			"namespace":   meta.Namespace,
			"labels":      toStringMap(meta.Labels),
			"annotations": toStringMap(meta.Annotations),
		},
		"spec": routeSpec,
	}}

	_, err := a.dynamic.Resource(routeGVR).Namespace(spec.Namespace).Create(ctx, route, metav1.CreateOptions{})
	if err != nil && !k8serrors.IsAlreadyExists(err) {
		return fmt.Errorf("create route %s: %w", spec.Name, err)
	}
	return nil
}

// Unstructured content must hold only JSON-compatible types.
func toStringMap(in map[string]string) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
