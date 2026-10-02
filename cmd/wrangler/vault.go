package main

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/api"
)

type vaultProvisioner struct {
	client *api.Client
}

func newVaultProvisioner(client *api.Client) *vaultProvisioner {
	return &vaultProvisioner{client: client}
}

// EnsureEngine mounts a KV v2 engine at engine, tolerating one that already
// exists so a retried request does not fail on its own earlier work.
func (v *vaultProvisioner) EnsureEngine(ctx context.Context, engine string) error {
	mounts, err := v.client.Sys().ListMountsWithContext(ctx)
	if err != nil {
		return fmt.Errorf("list vault mounts: %w", err)
	}
	if _, ok := mounts[engine+"/"]; ok {
		return nil
	}

	err = v.client.Sys().MountWithContext(ctx, engine, &api.MountInput{
		Type:    "kv",
		Options: map[string]string{"version": "2"},
	})
	if err != nil {
		return fmt.Errorf("mount vault engine %s: %w", engine, err)
	}
	return nil
}

// Exactly what internal/vault calls: List on metadata, Read on data. Nothing
// in raven writes to Vault, so nothing here grants write.
const policyTemplate = `path "%[1]s/metadata" {
  capabilities = ["list"]
}

path "%[1]s/metadata/*" {
  capabilities = ["list", "read"]
}

path "%[1]s/data/*" {
  capabilities = ["read"]
}
`

// EnsurePolicy writes the read-only policy for engine. Writing an existing
// policy is already idempotent in Vault.
func (v *vaultProvisioner) EnsurePolicy(ctx context.Context, name, engine string) error {
	policy := fmt.Sprintf(policyTemplate, engine)
	if err := v.client.Sys().PutPolicyWithContext(ctx, name, policy); err != nil {
		return fmt.Errorf("put vault policy %s: %w", name, err)
	}
	return nil
}

// Ravens are long-lived. Vault caps this to the system max_lease_ttl and only
// warns, so the grant is verified below rather than trusted.
const tokenTTL = "175200h" // 20 years

var wantTokenTTL = 175200 * time.Hour

// CreateToken mints a long-lived token bound to policy. The caller is
// responsible for storing it; it must never be logged.
func (v *vaultProvisioner) CreateToken(ctx context.Context, policy string) (string, error) {
	renewable := true
	secret, err := v.client.Auth().Token().CreateWithContext(ctx, &api.TokenCreateRequest{
		Policies:       []string{policy},
		TTL:            tokenTTL,
		ExplicitMaxTTL: tokenTTL,
		Renewable:      &renewable,
		// Orphan: a child dies with its parent, so rotating wrangler's own
		// token would revoke every raven in the fleet. Needs sudo on
		// auth/token/create.
		NoParent: true,
	})
	if err != nil {
		return "", fmt.Errorf("create vault token for policy %s: %w", policy, err)
	}
	token, err := secret.TokenID()
	if err != nil {
		return "", fmt.Errorf("read minted token id: %w", err)
	}

	granted, err := secret.TokenTTL()
	if err != nil {
		return "", fmt.Errorf("read minted token ttl: %w", err)
	}
	if granted < wantTokenTTL-time.Hour {
		if err := v.RevokeToken(ctx, token); err != nil {
			return "", fmt.Errorf("vault granted a %s token, want %s, and revoking it failed: %w", granted, wantTokenTTL, err)
		}
		return "", fmt.Errorf("vault granted a %s token, want %s: raise max_lease_ttl (vault said: %v)", granted, wantTokenTTL, secret.Warnings)
	}
	return token, nil
}

// RevokeToken revokes a token and everything issued beneath it.
func (v *vaultProvisioner) RevokeToken(ctx context.Context, token string) error {
	return v.client.Auth().Token().RevokeTreeWithContext(ctx, token)
}
