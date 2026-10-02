package main

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/volck/raven/internal/provision"
)

func TestClusterApplier_ApplyService(t *testing.T) {
	t.Parallel()

	client := k8sfake.NewSimpleClientset(preflightObjects()...)
	applier := newClusterApplier(client, nil, testDefaults())
	spec := wranglerSpec()

	if err := applier.ApplyService(context.Background(), spec); err != nil {
		t.Fatalf("ApplyService() error = %v", err)
	}
	svc, err := client.CoreV1().Services(spec.Namespace).Get(context.Background(), spec.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get service: %v", err)
	}

	if svc.Spec.Type != corev1.ServiceTypeClusterIP {
		t.Errorf("type = %q, want ClusterIP", svc.Spec.Type)
	}
	if got := len(svc.Spec.Ports); got != 1 {
		t.Fatalf("got %d ports, want 1", got)
	}
	port := svc.Spec.Ports[0]
	if port.Port != ravenPort {
		t.Errorf("port = %d, want %d", port.Port, ravenPort)
	}
	if port.TargetPort.IntValue() != ravenPort {
		t.Errorf("targetPort = %v, want %d", port.TargetPort, ravenPort)
	}
	if port.Protocol != corev1.ProtocolTCP {
		t.Errorf("protocol = %q, want TCP", port.Protocol)
	}
	if svc.Labels[provision.LabelManagedBy] != provision.ManagedByWrangler {
		t.Errorf("service is not stamped as wrangler-managed: %v", svc.Labels)
	}
}

// A selector that matches nothing yields a Service with no endpoints and no
// error, so it is checked against the pod labels the applier actually sets.
func TestClusterApplier_ApplyService_SelectsTheDeployment(t *testing.T) {
	t.Parallel()

	client := k8sfake.NewSimpleClientset(preflightObjects()...)
	applier := newClusterApplier(client, nil, testDefaults())
	spec := wranglerSpec()

	if err := applier.ApplyDeployment(context.Background(), spec); err != nil {
		t.Fatalf("ApplyDeployment() error = %v", err)
	}
	if err := applier.ApplyService(context.Background(), spec); err != nil {
		t.Fatalf("ApplyService() error = %v", err)
	}

	deploy, err := client.AppsV1().Deployments(spec.Namespace).Get(context.Background(), spec.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	svc, err := client.CoreV1().Services(spec.Namespace).Get(context.Background(), spec.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get service: %v", err)
	}

	podLabels := deploy.Spec.Template.ObjectMeta.Labels
	if len(svc.Spec.Selector) == 0 {
		t.Fatal("service has an empty selector, which would match every pod in the namespace")
	}
	for key, want := range svc.Spec.Selector {
		if got, ok := podLabels[key]; !ok || got != want {
			t.Errorf("selector %s=%s does not match pod labels %v", key, want, podLabels)
		}
	}
}
