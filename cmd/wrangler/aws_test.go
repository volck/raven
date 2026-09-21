package main

import (
	"context"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/volck/raven/internal/provision"
)

func awsSpec() provision.RavenSpec {
	spec := wranglerSpec()
	spec.AWSWriteback = true
	return spec
}

func awsDefaultsConfig() ravenDefaults {
	defaults := testDefaults()
	defaults.AWS = awsSettings{
		Region:       "eu-north-1",
		SecretPrefix: "/nt/vault",
		RoleName:     "nt-los-vault-integration",
	}
	return defaults
}

// Writeback off is the default, and raven treats a missing AWS_WRITEBACK as
// false. Emitting nothing keeps the switch honest.
func TestClusterApplier_ApplyDeployment_WritebackDisabled(t *testing.T) {
	t.Parallel()

	deploy := applyDeploymentWith(t, wranglerSpec(), awsDefaultsConfig())

	for _, env := range deploy.Spec.Template.Spec.Containers[0].Env {
		if strings.HasPrefix(env.Name, "AWS_") {
			t.Errorf("writeback disabled but deployment carries %s", env.Name)
		}
	}
}

func TestClusterApplier_ApplyDeployment_WritebackEnabled(t *testing.T) {
	t.Parallel()

	deploy := applyDeploymentWith(t, awsSpec(), awsDefaultsConfig())
	container := deploy.Spec.Template.Spec.Containers[0]

	want := map[string]string{
		"AWS_WRITEBACK":     "true",
		"AWS_REGION":        "eu-north-1",
		"AWS_SECRET_PREFIX": "/nt/vault",
		"AWS_ROLE_NAME":     "nt-los-vault-integration",
	}
	for name, value := range want {
		env, ok := envOf(container, name)
		if !ok {
			t.Fatalf("missing env %s", name)
		}
		if env.Value != value {
			t.Errorf("%s = %q, want %q", name, env.Value, value)
		}
	}
}

// Credentials differ per raven and must never be inlined the way the existing
// hand-written manifests inline them.
func TestClusterApplier_ApplyDeployment_CredentialsByReference(t *testing.T) {
	t.Parallel()

	spec := awsSpec()
	deploy := applyDeploymentWith(t, spec, awsDefaultsConfig())
	container := deploy.Spec.Template.Spec.Containers[0]

	for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} {
		env, ok := envOf(container, name)
		if !ok {
			t.Fatalf("missing env %s", name)
		}
		if env.Value != "" {
			t.Errorf("%s carries a literal value %q", name, env.Value)
		}
		ref := env.ValueFrom.SecretKeyRef
		if ref == nil {
			t.Fatalf("%s is not read from a secret", name)
		}
		if got, want := ref.Name, awsCredentialsSecretName(spec); got != want {
			t.Errorf("%s secret = %q, want %q", name, got, want)
		}
		if ref.Key != name {
			t.Errorf("%s key = %q, want %q", name, ref.Key, name)
		}
	}
}

// The credentials secret is created out of band, so a typo must surface as a
// request error rather than a pod that cannot start.
func TestClusterApplier_Preflight_AWSCredentials(t *testing.T) {
	t.Parallel()

	spec := awsSpec()
	credentials := awsCredentialsSecretName(spec)

	tests := []struct {
		name    string
		objects []runtime.Object
		wantErr bool
	}{
		{
			name:    "credentials present",
			objects: append(preflightObjects(), secretObj(credentials, spec.Namespace)),
		},
		{
			name:    "credentials missing",
			objects: preflightObjects(),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			applier := newClusterApplier(fake.NewSimpleClientset(tc.objects...), nil, awsDefaultsConfig())
			err := applier.Preflight(context.Background(), spec, false)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error naming the missing credentials secret")
				}
				if !strings.Contains(err.Error(), credentials) {
					t.Errorf("error %q does not name %q", err, credentials)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// Writeback off must not demand credentials that will never be read.
func TestClusterApplier_Preflight_NoAWSCredentialsWhenDisabled(t *testing.T) {
	t.Parallel()

	applier := newClusterApplier(fake.NewSimpleClientset(preflightObjects()...), nil, awsDefaultsConfig())

	if err := applier.Preflight(context.Background(), wranglerSpec(), false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
