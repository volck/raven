package main

import (
	"context"
	"fmt"
	"sort"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/volck/raven/internal/provision"
)

const ravenPort = 8080

// ApplyDeployment creates the raven workload. The Vault token is referenced
// from its Secret, never copied into the pod spec.
func (a *clusterApplier) ApplyDeployment(ctx context.Context, spec provision.RavenSpec) error {
	meta := objectMeta(spec, spec.Name)
	if spec.RouteHost != "" {
		meta.Annotations[provision.AnnoTarget] = "https://" + spec.RouteHost
	}

	podLabels := map[string]string{provision.LabelManagedBy: provision.ManagedByWrangler}
	for key, value := range podSelector(spec) {
		podLabels[key] = value
	}

	deploy := &appsv1.Deployment{
		ObjectMeta: meta,
		Spec: appsv1.DeploymentSpec{
			Replicas:             ptr.To[int32](1),
			RevisionHistoryLimit: ptr.To[int32](5),
			Selector:             &metav1.LabelSelector{MatchLabels: podSelector(spec)},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: podLabels},
				Spec: corev1.PodSpec{
					ServiceAccountName: serviceAccountName(spec),
					Containers: []corev1.Container{{
						Name:            spec.Name,
						Image:           spec.Image,
						ImagePullPolicy: corev1.PullAlways,
						Ports: []corev1.ContainerPort{{
							ContainerPort: ravenPort,
							Protocol:      corev1.ProtocolTCP,
						}},
						Env:          a.containerEnv(spec),
						VolumeMounts: a.volumeMounts(),
					}},
					Volumes: a.volumes(),
				},
			},
		},
	}

	_, err := a.clientset.AppsV1().Deployments(spec.Namespace).Create(ctx, deploy, metav1.CreateOptions{})
	if err != nil && !k8serrors.IsAlreadyExists(err) {
		return fmt.Errorf("create deployment %s: %w", spec.Name, err)
	}
	return nil
}

func (a *clusterApplier) containerEnv(spec provision.RavenSpec) []corev1.EnvVar {
	env := []corev1.EnvVar{{
		Name: "VAULT_TOKEN",
		ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: tokenSecretName(spec)},
				Key:                  "token",
			},
		},
	}}

	perRaven := map[string]string{
		"MG_APP_NAME":   spec.Namespace,
		"REPO_URL":      spec.RepoURL,
		"SECRET_ENGINE": spec.SecretEngine,
		"DEST_ENV":      spec.DestEnv,
	}
	for _, name := range sortedKeys(perRaven) {
		env = append(env, corev1.EnvVar{Name: name, Value: perRaven[name]})
	}
	for _, name := range sortedKeys(a.defaults.Env) {
		env = append(env, corev1.EnvVar{Name: name, Value: a.defaults.Env[name]})
	}
	return append(env, a.awsEnv(spec)...)
}

func (a *clusterApplier) volumeMounts() []corev1.VolumeMount {
	mounts := make([]corev1.VolumeMount, 0, len(a.defaults.Mounts))
	for _, m := range a.defaults.Mounts {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      m.SecretName,
			MountPath: m.MountPath,
			ReadOnly:  m.ReadOnly,
		})
	}
	return mounts
}

func (a *clusterApplier) volumes() []corev1.Volume {
	volumes := make([]corev1.Volume, 0, len(a.defaults.Mounts))
	for _, m := range a.defaults.Mounts {
		source := &corev1.SecretVolumeSource{
			SecretName:  m.SecretName,
			DefaultMode: ptr.To[int32](420),
		}
		if m.Key != "" {
			source.Items = []corev1.KeyToPath{{Key: m.Key, Path: m.Path}}
		}
		volumes = append(volumes, corev1.Volume{
			Name:         m.SecretName,
			VolumeSource: corev1.VolumeSource{Secret: source},
		})
	}
	return volumes
}

// Deterministic env ordering keeps re-applies from looking like changes.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
