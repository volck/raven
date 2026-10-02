package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/volck/raven/internal/provision"
)

const testToken = "s.sometoken"

func applyDeployment(t *testing.T) *appsv1.Deployment {
	t.Helper()

	return applyDeploymentWith(t, wranglerSpec(), testDefaults())
}

func applyDeploymentWith(t *testing.T, spec provision.RavenSpec, defaults ravenDefaults) *appsv1.Deployment {
	t.Helper()

	client := k8sfake.NewSimpleClientset(preflightObjects()...)
	applier := newClusterApplier(client, nil, defaults)

	if err := applier.ApplyDeployment(context.Background(), spec); err != nil {
		t.Fatalf("ApplyDeployment() error = %v", err)
	}
	deploy, err := client.AppsV1().Deployments(spec.Namespace).Get(context.Background(), spec.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	return deploy
}

func envOf(container corev1.Container, name string) (corev1.EnvVar, bool) {
	for _, e := range container.Env {
		if e.Name == name {
			return e, true
		}
	}
	return corev1.EnvVar{}, false
}

// deploymentString renders the whole object so a leaked secret cannot hide in
// a field the assertions do not name.
func deploymentString(t *testing.T, deploy *appsv1.Deployment) string {
	t.Helper()

	data, err := json.Marshal(deploy)
	if err != nil {
		t.Fatalf("marshal deployment: %v", err)
	}
	return string(data)
}

func TestClusterApplier_ApplyDeployment_Identity(t *testing.T) {
	t.Parallel()

	deploy := applyDeployment(t)
	spec := wranglerSpec()

	if got := deploy.Labels[provision.LabelManagedBy]; got != provision.ManagedByWrangler {
		t.Errorf("label %s = %q, want %q", provision.LabelManagedBy, got, provision.ManagedByWrangler)
	}
	if got := deploy.Annotations[provision.AnnoTarget]; got != "https://"+spec.RouteHost {
		t.Errorf("annotation %s = %q, want %q", provision.AnnoTarget, got, "https://"+spec.RouteHost)
	}
	if got := deploy.Annotations[provision.AnnoEngine]; got != spec.SecretEngine {
		t.Errorf("annotation %s = %q, want %q", provision.AnnoEngine, got, spec.SecretEngine)
	}

	// A selector that does not match the pod template produces a Deployment
	// that never becomes ready.
	if got := deploy.Spec.Selector.MatchLabels["app"]; got != spec.Name {
		t.Errorf("selector app = %q, want %q", got, spec.Name)
	}
	if got := deploy.Spec.Template.Labels["app"]; got != spec.Name {
		t.Errorf("template label app = %q, want %q", got, spec.Name)
	}
	if got := deploy.Spec.Template.Spec.ServiceAccountName; got != "ssg-dev-cleaner" {
		t.Errorf("serviceAccountName = %q, want %q", got, "ssg-dev-cleaner")
	}
}

func TestClusterApplier_ApplyDeployment_Env(t *testing.T) {
	t.Parallel()

	deploy := applyDeployment(t)
	spec := wranglerSpec()
	container := deploy.Spec.Template.Spec.Containers[0]

	if container.Image != spec.Image {
		t.Errorf("image = %q, want %q", container.Image, spec.Image)
	}

	perRaven := map[string]string{
		"REPO_URL":      spec.RepoURL,
		"SECRET_ENGINE": spec.SecretEngine,
		"DEST_ENV":      spec.DestEnv,
	}
	for name, want := range perRaven {
		env, ok := envOf(container, name)
		if !ok {
			t.Errorf("env %s missing", name)
			continue
		}
		if env.Value != want {
			t.Errorf("env %s = %q, want %q", name, env.Value, want)
		}
	}

	// Cluster-wide defaults are wrangler configuration, not request input.
	env, ok := envOf(container, "VAULTENDPOINT")
	if !ok || env.Value != "https://vault.example.com/" {
		t.Errorf("env VAULTENDPOINT = %q (present=%v), want %q", env.Value, ok, "https://vault.example.com/")
	}
}

// The Vault token reaches the pod by reference. A literal copy in the pod spec
// would be readable by anyone who can get the Deployment.
func TestClusterApplier_ApplyDeployment_TokenByReference(t *testing.T) {
	t.Parallel()

	client := k8sfake.NewSimpleClientset(preflightObjects()...)
	applier := newClusterApplier(client, nil, testDefaults())
	spec := wranglerSpec()
	ctx := context.Background()

	if err := applier.ApplyTokenSecret(ctx, spec, testToken); err != nil {
		t.Fatalf("ApplyTokenSecret() error = %v", err)
	}
	if err := applier.ApplyDeployment(ctx, spec); err != nil {
		t.Fatalf("ApplyDeployment() error = %v", err)
	}
	deploy, err := client.AppsV1().Deployments("ssg").Get(ctx, "ssg-dev", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get deployment: %v", err)
	}

	container := deploy.Spec.Template.Spec.Containers[0]
	env, ok := envOf(container, "VAULT_TOKEN")
	if !ok {
		t.Fatal("env VAULT_TOKEN missing")
	}
	if env.Value != "" {
		t.Errorf("VAULT_TOKEN carries a literal value %q, want a secretKeyRef", env.Value)
	}
	ref := env.ValueFrom
	if ref == nil || ref.SecretKeyRef == nil {
		t.Fatal("VAULT_TOKEN has no secretKeyRef")
	}
	if ref.SecretKeyRef.Name != "vault-ssg-dev-token" || ref.SecretKeyRef.Key != "token" {
		t.Errorf("secretKeyRef = %s/%s, want vault-ssg-dev-token/token", ref.SecretKeyRef.Name, ref.SecretKeyRef.Key)
	}

	if strings.Contains(deploymentString(t, deploy), testToken) {
		t.Error("the token value appears verbatim in the Deployment")
	}
}

func TestClusterApplier_ApplyDeployment_Mounts(t *testing.T) {
	t.Parallel()

	deploy := applyDeployment(t)
	podSpec := deploy.Spec.Template.Spec

	for _, mount := range testDefaults().Mounts {
		var found bool
		for _, vm := range podSpec.Containers[0].VolumeMounts {
			if vm.MountPath == mount.MountPath {
				found = true
			}
		}
		if !found {
			t.Errorf("no volumeMount at %s for secret %s", mount.MountPath, mount.SecretName)
		}

		found = false
		for _, v := range podSpec.Volumes {
			if v.Secret != nil && v.Secret.SecretName == mount.SecretName {
				found = true
			}
		}
		if !found {
			t.Errorf("no volume for secret %s", mount.SecretName)
		}
	}
}
