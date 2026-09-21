package main

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/volck/raven/internal/provision"
)

func TestClusterApplier_ApplyTokenSecret(t *testing.T) {
	t.Parallel()

	client := k8sfake.NewSimpleClientset(preflightObjects()...)
	applier := newClusterApplier(client, nil, testDefaults())
	spec := wranglerSpec()

	if err := applier.ApplyTokenSecret(context.Background(), spec, "s.sometoken"); err != nil {
		t.Fatalf("ApplyTokenSecret() error = %v", err)
	}

	secret, err := client.CoreV1().Secrets("ssg").Get(context.Background(), "vault-ssg-dev-token", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get token secret: %v", err)
	}
	if got := string(secret.Data["token"]); got != "s.sometoken" {
		t.Errorf("secret data[token] = %q, want %q", got, "s.sometoken")
	}
	if got := secret.Labels[provision.LabelManagedBy]; got != provision.ManagedByWrangler {
		t.Errorf("label %s = %q, want %q", provision.LabelManagedBy, got, provision.ManagedByWrangler)
	}
	if got := secret.Annotations[provision.AnnoEngine]; got != spec.SecretEngine {
		t.Errorf("annotation %s = %q, want %q", provision.AnnoEngine, got, spec.SecretEngine)
	}
}

// The token Secret is the idempotency guard: if it already exists a retry must
// not mint and store a second Vault token.
func TestClusterApplier_TokenSecretExists(t *testing.T) {
	t.Parallel()

	client := k8sfake.NewSimpleClientset(preflightObjects()...)
	applier := newClusterApplier(client, nil, testDefaults())
	spec := wranglerSpec()
	ctx := context.Background()

	exists, err := applier.TokenSecretExists(ctx, spec)
	if err != nil {
		t.Fatalf("TokenSecretExists() error = %v", err)
	}
	if exists {
		t.Fatal("TokenSecretExists() = true before the secret was created")
	}

	if err := applier.ApplyTokenSecret(ctx, spec, "s.sometoken"); err != nil {
		t.Fatalf("ApplyTokenSecret() error = %v", err)
	}

	exists, err = applier.TokenSecretExists(ctx, spec)
	if err != nil {
		t.Fatalf("TokenSecretExists() error = %v", err)
	}
	if !exists {
		t.Error("TokenSecretExists() = false after the secret was created")
	}
}
