package main

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/volck/raven/internal/provision"
)

// podSelector is the label set shared by the Deployment template and the
// Service, so the two cannot drift apart.
func podSelector(spec provision.RavenSpec) map[string]string {
	return map[string]string{"app": spec.Name}
}

func (a *clusterApplier) ApplyService(ctx context.Context, spec provision.RavenSpec) error {
	svc := &corev1.Service{
		ObjectMeta: objectMeta(spec, spec.Name),
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: podSelector(spec),
			Ports: []corev1.ServicePort{{
				Name:       "http",
				Port:       ravenPort,
				TargetPort: intstr.FromInt32(ravenPort),
				Protocol:   corev1.ProtocolTCP,
			}},
		},
	}

	_, err := a.clientset.CoreV1().Services(spec.Namespace).Create(ctx, svc, metav1.CreateOptions{})
	if err != nil && !k8serrors.IsAlreadyExists(err) {
		return fmt.Errorf("create service %s: %w", spec.Name, err)
	}
	return nil
}
