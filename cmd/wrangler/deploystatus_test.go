package main

import (
	"context"
	"errors"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/volck/raven/internal/provision"
)

func ravenDeployment(name, namespace string, desired, ready int32) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"app":                    name,
				provision.LabelManagedBy: provision.ManagedByWrangler,
			},
			Annotations: map[string]string{provision.AnnoEngine: "kv"},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &desired,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
		},
		Status: appsv1.DeploymentStatus{
			Replicas:          desired,
			ReadyReplicas:     ready,
			AvailableReplicas: ready,
			UpdatedReplicas:   desired,
			Conditions: []appsv1.DeploymentCondition{{
				Type:    appsv1.DeploymentAvailable,
				Status:  corev1.ConditionFalse,
				Reason:  "MinimumReplicasUnavailable",
				Message: "Deployment does not have minimum availability.",
			}},
		},
	}
}

func ravenPod(name, namespace, app string, waiting *corev1.ContainerStateWaiting, restarts int32) *corev1.Pod {
	status := corev1.ContainerStatus{Name: app, RestartCount: restarts, Ready: waiting == nil}
	if waiting != nil {
		status.State = corev1.ContainerState{Waiting: waiting}
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{"app": app},
		},
		Status: corev1.PodStatus{
			Phase:             corev1.PodPending,
			ContainerStatuses: []corev1.ContainerStatus{status},
		},
	}
}

func TestDeploymentReader_ReportsReplicasAndConditions(t *testing.T) {
	t.Parallel()

	reader := newDeploymentReader(k8sfake.NewSimpleClientset(
		ravenDeployment("ssg-dev", "ssg", 1, 0),
	), "ssg")

	got, err := reader.Status(context.Background(), "ssg-dev")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}

	if got.Namespace != "ssg" {
		t.Errorf("namespace = %q, want ssg", got.Namespace)
	}
	if got.Desired != 1 || got.Ready != 0 {
		t.Errorf("desired/ready = %d/%d, want 1/0", got.Desired, got.Ready)
	}
	if len(got.Conditions) != 1 {
		t.Fatalf("conditions = %d, want 1", len(got.Conditions))
	}
	if got.Conditions[0].Reason != "MinimumReplicasUnavailable" {
		t.Errorf("condition reason = %q", got.Conditions[0].Reason)
	}
}

// The reason a raven will not start is the whole point of the endpoint.
func TestDeploymentReader_ReportsPodFailureReason(t *testing.T) {
	t.Parallel()

	reader := newDeploymentReader(k8sfake.NewSimpleClientset(
		ravenDeployment("ssg-dev", "ssg", 1, 0),
		ravenPod("ssg-dev-abc", "ssg", "ssg-dev", &corev1.ContainerStateWaiting{
			Reason:  "ImagePullBackOff",
			Message: "Back-off pulling image",
		}, 3),
		ravenPod("other-xyz", "ssg", "other-raven", nil, 0),
	), "ssg")

	got, err := reader.Status(context.Background(), "ssg-dev")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}

	if len(got.Pods) != 1 {
		t.Fatalf("pods = %d, want 1 (selector must exclude other ravens)", len(got.Pods))
	}
	pod := got.Pods[0]
	if pod.Reason != "ImagePullBackOff" {
		t.Errorf("reason = %q, want ImagePullBackOff", pod.Reason)
	}
	if pod.Restarts != 3 {
		t.Errorf("restarts = %d, want 3", pod.Restarts)
	}
	if pod.Ready {
		t.Error("pod reported ready while waiting on an image pull")
	}
}

func TestDeploymentReader_UnknownRaven(t *testing.T) {
	t.Parallel()

	reader := newDeploymentReader(k8sfake.NewSimpleClientset(), "")

	if _, err := reader.Status(context.Background(), "nope"); !errors.Is(err, errRavenNotFound) {
		t.Fatalf("error = %v, want errRavenNotFound", err)
	}
}

// Scoping the reader to one namespace is what lets wrangler run with a Role
// instead of a ClusterRole.
func TestDeploymentReader_ScopedToNamespace(t *testing.T) {
	t.Parallel()

	client := k8sfake.NewSimpleClientset(
		ravenDeployment("ssg-dev", "other", 1, 1),
	)

	if _, err := newDeploymentReader(client, "ssg").Status(context.Background(), "ssg-dev"); !errors.Is(err, errRavenNotFound) {
		t.Fatalf("error = %v, want errRavenNotFound for a deployment outside the namespace", err)
	}

	if _, err := newDeploymentReader(client, "other").Status(context.Background(), "ssg-dev"); err != nil {
		t.Fatalf("Status in its own namespace: %v", err)
	}
}

// Only wrangler-managed deployments are reported: an unlabelled workload that
// happens to share the name is somebody else's.
func TestDeploymentReader_IgnoresUnmanagedDeployment(t *testing.T) {
	t.Parallel()

	unmanaged := ravenDeployment("ssg-dev", "ssg", 1, 1)
	delete(unmanaged.Labels, provision.LabelManagedBy)

	reader := newDeploymentReader(k8sfake.NewSimpleClientset(unmanaged), "ssg")

	if _, err := reader.Status(context.Background(), "ssg-dev"); !errors.Is(err, errRavenNotFound) {
		t.Fatalf("error = %v, want errRavenNotFound", err)
	}
}
