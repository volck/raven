package main

import (
	"context"
	"testing"

	"github.com/volck/raven/internal/testutil"
)

func TestVaultProvisioner_EnsureEngine(t *testing.T) {
	t.Parallel()

	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()

	prov := newVaultProvisioner(cluster.Cores[0].Client)
	ctx := context.Background()

	if err := prov.EnsureEngine(ctx, "dev"); err != nil {
		t.Fatalf("EnsureEngine() error = %v", err)
	}

	mounts, err := cluster.Cores[0].Client.Sys().ListMounts()
	if err != nil {
		t.Fatalf("list mounts: %v", err)
	}
	mount, ok := mounts["dev/"]
	if !ok {
		t.Fatalf("mount dev/ not found, have %v", mountPaths(mounts))
	}
	if mount.Type != "kv" {
		t.Errorf("mount type = %q, want %q", mount.Type, "kv")
	}
	if got := mount.Options["version"]; got != "2" {
		t.Errorf("kv version = %q, want \"2\"", got)
	}
}

// A retry after a partial failure must not fail on the engine that the first
// attempt already created.
func TestVaultProvisioner_EnsureEngine_Idempotent(t *testing.T) {
	t.Parallel()

	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()

	prov := newVaultProvisioner(cluster.Cores[0].Client)
	ctx := context.Background()

	if err := prov.EnsureEngine(ctx, "dev"); err != nil {
		t.Fatalf("first EnsureEngine() error = %v", err)
	}
	if err := prov.EnsureEngine(ctx, "dev"); err != nil {
		t.Fatalf("second EnsureEngine() error = %v, want nil", err)
	}
}

func mountPaths[T any](mounts map[string]T) []string {
	paths := make([]string, 0, len(mounts))
	for p := range mounts {
		paths = append(paths, p)
	}
	return paths
}
