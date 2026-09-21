package main

import (
	"context"
	"strings"
	"testing"

	"github.com/volck/raven/internal/testutil"
)

func TestVaultProvisioner_EnsurePolicy(t *testing.T) {
	t.Parallel()

	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client
	prov := newVaultProvisioner(client)
	ctx := context.Background()

	if err := prov.EnsurePolicy(ctx, "raven-ssg-dev", "dev"); err != nil {
		t.Fatalf("EnsurePolicy() error = %v", err)
	}

	policy, err := client.Sys().GetPolicy("raven-ssg-dev")
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}

	for _, want := range []string{
		`path "dev/metadata"`,
		`path "dev/metadata/*"`,
		`path "dev/data/*"`,
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("policy missing %s:\n%s", want, policy)
		}
	}

	// Raven only ever reads from Vault. A minted token that can write is a
	// standing hazard, so the absence of write verbs is the point of the test.
	for _, forbidden := range []string{"create", "update", "delete", "patch", "sudo", "root"} {
		if strings.Contains(policy, forbidden) {
			t.Errorf("policy grants %q, want read-only:\n%s", forbidden, policy)
		}
	}
}

func TestVaultProvisioner_EnsurePolicy_Idempotent(t *testing.T) {
	t.Parallel()

	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()

	prov := newVaultProvisioner(cluster.Cores[0].Client)
	ctx := context.Background()

	if err := prov.EnsurePolicy(ctx, "raven-ssg-dev", "dev"); err != nil {
		t.Fatalf("first EnsurePolicy() error = %v", err)
	}
	if err := prov.EnsurePolicy(ctx, "raven-ssg-dev", "dev"); err != nil {
		t.Fatalf("second EnsurePolicy() error = %v, want nil", err)
	}
}
