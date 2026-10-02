package main

import (
	"context"
	"testing"
	"time"

	kvsecrets "github.com/hashicorp/vault-plugin-secrets-kv"
	"github.com/hashicorp/vault/api"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/logical"
	hashivault "github.com/hashicorp/vault/vault"
)

// vaultCluster starts an in-process Vault whose system max_lease_ttl is
// maxLeaseTTL. Zero means Vault's 768h default, which is what an unprepared
// Vault looks like.
func vaultCluster(t *testing.T, maxLeaseTTL time.Duration) *hashivault.TestCluster {
	t.Helper()

	cluster := hashivault.NewTestCluster(t, &hashivault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{"kv": kvsecrets.Factory},
		MaxLeaseTTL:     maxLeaseTTL,
	}, &hashivault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	t.Cleanup(cluster.Cleanup)
	return cluster
}

// provisionedVault returns a cluster configured for long-lived tokens, with
// the engine and policy already in place.
func provisionedVault(t *testing.T) (*hashivault.TestCluster, *vaultProvisioner) {
	t.Helper()

	cluster := vaultCluster(t, 21*365*24*time.Hour)
	prov := newVaultProvisioner(cluster.Cores[0].Client)
	ctx := context.Background()

	if err := prov.EnsureEngine(ctx, "dev"); err != nil {
		t.Fatalf("EnsureEngine() error = %v", err)
	}
	if err := prov.EnsurePolicy(ctx, "raven-ssg-dev", "dev"); err != nil {
		t.Fatalf("EnsurePolicy() error = %v", err)
	}
	return cluster, prov
}

// A child token dies with its parent, so a raven minted under wrangler's own
// token would lose Vault access the moment that token is rotated or revoked.
func TestVaultProvisioner_CreateToken_IsOrphan(t *testing.T) {
	t.Parallel()

	cluster, prov := provisionedVault(t)
	root := cluster.Cores[0].Client
	ctx := context.Background()

	token, err := prov.CreateToken(ctx, "raven-ssg-dev")
	if err != nil {
		t.Fatalf("CreateToken() error = %v", err)
	}

	self, err := root.Auth().Token().LookupWithContext(ctx, token)
	if err != nil {
		t.Fatalf("lookup minted token: %v", err)
	}
	if orphan, _ := self.Data["orphan"].(bool); !orphan {
		t.Errorf("minted token is a child of wrangler's token, want an orphan")
	}
}

func TestVaultProvisioner_CreateToken(t *testing.T) {
	t.Parallel()

	cluster, prov := provisionedVault(t)
	root := cluster.Cores[0].Client
	ctx := context.Background()

	token, err := prov.CreateToken(ctx, "raven-ssg-dev")
	if err != nil {
		t.Fatalf("CreateToken() error = %v", err)
	}
	if token == "" {
		t.Fatal("CreateToken() returned an empty token")
	}

	ravenClient, err := root.Clone()
	if err != nil {
		t.Fatalf("clone client: %v", err)
	}
	ravenClient.SetToken(token)

	self, err := ravenClient.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		t.Fatalf("lookup-self with minted token: %v", err)
	}

	policies, err := self.TokenPolicies()
	if err != nil {
		t.Fatalf("TokenPolicies: %v", err)
	}
	if !contains(policies, "raven-ssg-dev") {
		t.Errorf("token policies = %v, want to include raven-ssg-dev", policies)
	}

	ttl, err := self.TokenTTL()
	if err != nil {
		t.Fatalf("TokenTTL: %v", err)
	}
	if min := 19 * 365 * 24 * time.Hour; ttl < min {
		t.Errorf("token TTL = %s, want at least %s", ttl, min)
	}
}

// Vault truncates an over-long TTL to max_lease_ttl and reports it only as a
// warning. Accepting that quietly would strand the raven when the token dies,
// long after anyone connects the outage to provisioning.
func TestVaultProvisioner_CreateToken_RefusesTruncatedTTL(t *testing.T) {
	t.Parallel()

	cluster := vaultCluster(t, 0)
	root := cluster.Cores[0].Client
	prov := newVaultProvisioner(root)
	ctx := context.Background()

	if err := prov.EnsureEngine(ctx, "dev"); err != nil {
		t.Fatalf("EnsureEngine() error = %v", err)
	}
	if err := prov.EnsurePolicy(ctx, "raven-ssg-dev", "dev"); err != nil {
		t.Fatalf("EnsurePolicy() error = %v", err)
	}

	before := tokenAccessors(t, root)

	token, err := prov.CreateToken(ctx, "raven-ssg-dev")
	if err == nil {
		t.Fatalf("CreateToken() = %q, nil; want an error when Vault caps the TTL", token)
	}
	if token != "" {
		t.Errorf("CreateToken() returned token %q alongside its error, want empty", token)
	}

	// The truncated token must not be left behind as an orphan credential.
	if after := tokenAccessors(t, root); after != before {
		t.Errorf("token accessors went from %d to %d, want the capped token revoked", before, after)
	}
}

// Asserting the capability rather than the policy text: this is what actually
// stops a leaked raven token from mutating Vault.
func TestVaultProvisioner_CreateToken_ReadOnlyInPractice(t *testing.T) {
	t.Parallel()

	cluster, prov := provisionedVault(t)
	root := cluster.Cores[0].Client
	ctx := context.Background()

	if _, err := root.Logical().WriteWithContext(ctx, "dev/data/example", map[string]interface{}{
		"data": map[string]interface{}{"key": "value"},
	}); err != nil {
		t.Fatalf("seed secret: %v", err)
	}

	token, err := prov.CreateToken(ctx, "raven-ssg-dev")
	if err != nil {
		t.Fatalf("CreateToken() error = %v", err)
	}
	ravenClient, err := root.Clone()
	if err != nil {
		t.Fatalf("clone client: %v", err)
	}
	ravenClient.SetToken(token)

	if _, err := ravenClient.Logical().ReadWithContext(ctx, "dev/data/example"); err != nil {
		t.Errorf("raven token cannot read its own engine: %v", err)
	}
	if _, err := ravenClient.Logical().ListWithContext(ctx, "dev/metadata"); err != nil {
		t.Errorf("raven token cannot list its own engine: %v", err)
	}
	if _, err := ravenClient.Logical().WriteWithContext(ctx, "dev/data/example", map[string]interface{}{
		"data": map[string]interface{}{"key": "mutated"},
	}); err == nil {
		t.Error("raven token was able to write to Vault, want permission denied")
	}
}

func tokenAccessors(t *testing.T, root *api.Client) int {
	t.Helper()

	secret, err := root.Logical().List("auth/token/accessors")
	if err != nil {
		t.Fatalf("list token accessors: %v", err)
	}
	if secret == nil || secret.Data["keys"] == nil {
		return 0
	}
	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		t.Fatalf("accessors keys have type %T, want []interface{}", secret.Data["keys"])
	}
	return len(keys)
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
