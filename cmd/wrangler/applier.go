package main

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/volck/raven/internal/provision"
)

// mountedSecret is a Secret the raven pod mounts. Preflight checks these and
// the pod spec is built from them, so the two cannot disagree.
type mountedSecret struct {
	SecretName string
	MountPath  string
	Key        string
	Path       string
	ReadOnly   bool
}

// ravenDefaults holds the settings shared by every raven in a cluster. They
// are wrangler configuration rather than per-request input.
type ravenDefaults struct {
	Env           map[string]string
	Mounts        []mountedSecret
	AWS           awsSettings
	ClusterDomain string
}

type clusterApplier struct {
	clientset kubernetes.Interface
	dynamic   dynamic.Interface
	defaults  ravenDefaults
}

func newClusterApplier(clientset kubernetes.Interface, dyn dynamic.Interface, defaults ravenDefaults) *clusterApplier {
	return &clusterApplier{clientset: clientset, dynamic: dyn, defaults: defaults}
}

func serviceAccountName(spec provision.RavenSpec) string {
	return spec.Name + "-cleaner"
}

func tokenSecretName(spec provision.RavenSpec) string {
	return "vault-" + spec.Name + "-token"
}

func objectMeta(spec provision.RavenSpec, name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:      name,
		Namespace: spec.Namespace,
		Labels: map[string]string{
			"app":                    spec.Name,
			provision.LabelManagedBy: provision.ManagedByWrangler,
		},
		Annotations: map[string]string{
			provision.AnnoEngine: spec.SecretEngine,
		},
	}
}

// ApplyTokenSecret stores the Vault token. It is a plain Secret: it is created
// in-cluster and never rendered to git.
func (a *clusterApplier) ApplyTokenSecret(ctx context.Context, spec provision.RavenSpec, token string) error {
	secret := &corev1.Secret{
		ObjectMeta: objectMeta(spec, tokenSecretName(spec)),
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"token": []byte(token)},
	}
	_, err := a.clientset.CoreV1().Secrets(spec.Namespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil && !k8serrors.IsAlreadyExists(err) {
		return fmt.Errorf("create secret %s: %w", secret.Name, err)
	}
	return nil
}

// TokenSecretExists reports whether this raven already has a stored token, so
// a retried request does not mint a second one.
func (a *clusterApplier) TokenSecretExists(ctx context.Context, spec provision.RavenSpec) (bool, error) {
	_, err := a.clientset.CoreV1().Secrets(spec.Namespace).Get(ctx, tokenSecretName(spec), metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("get secret %s: %w", tokenSecretName(spec), err)
	}
	return true, nil
}

// Preflight verifies the things a raven Deployment mounts or runs as but does
// not own. Kubernetes would accept the Deployment without them and leave the
// pod unable to start, so every prerequisite is reported at once.
func (a *clusterApplier) Preflight(ctx context.Context, spec provision.RavenSpec, force bool) error {
	var missing []error

	// A live raven is never adopted: reprovisioning would repoint it at a
	// different repository or engine. force replaces it instead.
	if !force {
		switch _, err := a.clientset.AppsV1().Deployments(spec.Namespace).Get(ctx, spec.Name, metav1.GetOptions{}); {
		case err == nil:
			missing = append(missing, fmt.Errorf("raven %s already exists in namespace %s", spec.Name, spec.Namespace))
		case !k8serrors.IsNotFound(err):
			missing = append(missing, fmt.Errorf("check deployment %s: %w", spec.Name, err))
		}
	}

	sa := serviceAccountName(spec)
	if _, err := a.clientset.CoreV1().ServiceAccounts(spec.Namespace).Get(ctx, sa, metav1.GetOptions{}); err != nil {
		missing = append(missing, describeMissing(err, "serviceaccount", sa))
	}

	for _, mount := range a.defaults.Mounts {
		if _, err := a.clientset.CoreV1().Secrets(spec.Namespace).Get(ctx, mount.SecretName, metav1.GetOptions{}); err != nil {
			missing = append(missing, describeMissing(err, "secret", mount.SecretName))
		}
	}

	if spec.AWSWriteback {
		if err := a.defaults.AWS.complete(); err != nil {
			missing = append(missing, err)
		}
		credentials := awsCredentialsSecretName(spec)
		if _, err := a.clientset.CoreV1().Secrets(spec.Namespace).Get(ctx, credentials, metav1.GetOptions{}); err != nil {
			missing = append(missing, describeMissing(err, "secret", credentials))
		}
	}

	return errors.Join(missing...)
}

func describeMissing(err error, kind, name string) error {
	if k8serrors.IsNotFound(err) {
		return fmt.Errorf("%s %s does not exist", kind, name)
	}
	return fmt.Errorf("check %s %s: %w", kind, name, err)
}
