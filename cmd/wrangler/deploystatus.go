package main

import (
	"context"
	"errors"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/volck/raven/internal/provision"
)

// errRavenNotFound reports that no wrangler-managed deployment carries the name.
var errRavenNotFound = errors.New("raven not found")

type deploymentCondition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

type podStatus struct {
	Name     string `json:"name"`
	Phase    string `json:"phase"`
	Ready    bool   `json:"ready"`
	Restarts int32  `json:"restarts"`
	// Reason carries the container's stuck state: ImagePullBackOff,
	// CrashLoopBackOff and friends.
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

type deploymentStatus struct {
	Name       string                `json:"name"`
	Namespace  string                `json:"namespace"`
	Engine     string                `json:"engine,omitempty"`
	Desired    int32                 `json:"desired"`
	Ready      int32                 `json:"ready"`
	Available  int32                 `json:"available"`
	Updated    int32                 `json:"updated"`
	Conditions []deploymentCondition `json:"conditions"`
	Pods       []podStatus           `json:"pods"`
}

type deploymentReader struct {
	clientset kubernetes.Interface
	// namespace empty reads across all namespaces, which needs a ClusterRole.
	namespace string
}

func newDeploymentReader(clientset kubernetes.Interface, namespace string) *deploymentReader {
	return &deploymentReader{clientset: clientset, namespace: namespace}
}

// Status reports how the raven's workload is actually doing.
func (r *deploymentReader) Status(ctx context.Context, name string) (*deploymentStatus, error) {
	deploys, err := r.clientset.AppsV1().Deployments(r.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: provision.LabelManagedBy + "=" + provision.ManagedByWrangler,
	})
	if err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}

	var deploy *appsv1.Deployment
	for i := range deploys.Items {
		if deploys.Items[i].Name == name {
			deploy = &deploys.Items[i]
			break
		}
	}
	if deploy == nil {
		return nil, fmt.Errorf("%s: %w", name, errRavenNotFound)
	}

	status := &deploymentStatus{
		Name:       deploy.Name,
		Namespace:  deploy.Namespace,
		Engine:     deploy.Annotations[provision.AnnoEngine],
		Desired:    desiredReplicas(deploy),
		Ready:      deploy.Status.ReadyReplicas,
		Available:  deploy.Status.AvailableReplicas,
		Updated:    deploy.Status.UpdatedReplicas,
		Conditions: []deploymentCondition{},
		Pods:       []podStatus{},
	}
	for _, cond := range deploy.Status.Conditions {
		status.Conditions = append(status.Conditions, deploymentCondition{
			Type:    string(cond.Type),
			Status:  string(cond.Status),
			Reason:  cond.Reason,
			Message: cond.Message,
		})
	}

	pods, err := r.pods(ctx, deploy)
	if err != nil {
		return nil, err
	}
	status.Pods = pods

	return status, nil
}

func (r *deploymentReader) pods(ctx context.Context, deploy *appsv1.Deployment) ([]podStatus, error) {
	if deploy.Spec.Selector == nil {
		return []podStatus{}, nil
	}
	selector, err := metav1.LabelSelectorAsSelector(deploy.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("deployment selector: %w", err)
	}

	list, err := r.clientset.CoreV1().Pods(deploy.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	out := make([]podStatus, 0, len(list.Items))
	for i := range list.Items {
		out = append(out, summarisePod(&list.Items[i]))
	}
	return out, nil
}

func summarisePod(pod *corev1.Pod) podStatus {
	summary := podStatus{
		Name:  pod.Name,
		Phase: string(pod.Status.Phase),
		Ready: true,
	}
	if len(pod.Status.ContainerStatuses) == 0 {
		summary.Ready = false
		summary.Reason = pod.Status.Reason
		summary.Message = pod.Status.Message
	}

	for _, container := range pod.Status.ContainerStatuses {
		summary.Restarts += container.RestartCount
		if !container.Ready {
			summary.Ready = false
		}
		// First unhealthy container wins: one reason is enough to act on.
		if summary.Reason != "" {
			continue
		}
		switch {
		case container.State.Waiting != nil:
			summary.Reason = container.State.Waiting.Reason
			summary.Message = container.State.Waiting.Message
		case container.State.Terminated != nil && container.State.Terminated.ExitCode != 0:
			summary.Reason = container.State.Terminated.Reason
			summary.Message = container.State.Terminated.Message
		}
	}
	return summary
}

func desiredReplicas(deploy *appsv1.Deployment) int32 {
	if deploy.Spec.Replicas == nil {
		return 1
	}
	return *deploy.Spec.Replicas
}
