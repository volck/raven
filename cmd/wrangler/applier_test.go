package main

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/volck/raven/internal/provision"
)

func wranglerSpec() provision.RavenSpec {
	return provision.RavenSpec{
		Name:         "ssg-dev",
		Namespace:    "ssg",
		SecretEngine: "kv",
		DestEnv:      "dev",
		RepoURL:      "ssh://git@bitbucket.example.com:7999/sec/sealedsecrets-dev.git",
		Image:        "registry.example.com/ssg/raven@sha256:abc",
		RouteHost:    "ssg-dev-ssg.apps.example.com",
	}
}

func testDefaults() ravenDefaults {
	return ravenDefaults{
		Env: map[string]string{
			"VAULTENDPOINT": "https://vault.example.com/",
			"CLONE_PATH":    "/tmp/clone",
			"LOGLEVEL":      "DEBUG",
		},
		Mounts: []mountedSecret{
			{SecretName: "ssgsshprivatekey", MountPath: "/secret", Key: "ssh-privatekey", Path: "sshKey", ReadOnly: true},
			{SecretName: "ssc", MountPath: "/mg/secret/ssc"},
			{SecretName: "ntrootcert", MountPath: "/tmp/cert/"},
		},
	}
}

func namespaceObj(name string) runtime.Object {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func serviceAccountObj(name, namespace string) runtime.Object {
	return &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
}

func secretObj(name, namespace string) runtime.Object {
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
}

// Everything the reference Deployment depends on but does not create.
func preflightObjects() []runtime.Object {
	return []runtime.Object{
		namespaceObj("ssg"),
		serviceAccountObj("ssg-dev-cleaner", "ssg"),
		secretObj("ssgsshprivatekey", "ssg"),
		secretObj("ssc", "ssg"),
		secretObj("ntrootcert", "ssg"),
	}
}

func without(objects []runtime.Object, names ...string) []runtime.Object {
	kept := make([]runtime.Object, 0, len(objects))
	for _, obj := range objects {
		meta, ok := obj.(interface{ GetName() string })
		if !ok {
			kept = append(kept, obj)
			continue
		}
		drop := false
		for _, name := range names {
			if meta.GetName() == name {
				drop = true
			}
		}
		if !drop {
			kept = append(kept, obj)
		}
	}
	return kept
}

// Provisioning over a live raven would repoint it at a different repository or
// engine, so an existing Deployment is a conflict rather than something to adopt.
func TestClusterApplier_Preflight_RejectsExistingRaven(t *testing.T) {
	t.Parallel()

	spec := wranglerSpec()
	objects := append(preflightObjects(), ravenDeployment(spec.Name, spec.Namespace, 1, 1))

	err := newClusterApplier(k8sfake.NewSimpleClientset(objects...), nil, testDefaults()).
		Preflight(context.Background(), spec, false)
	if err == nil {
		t.Fatal("Preflight() = nil, want a conflict")
	}
	if !strings.Contains(err.Error(), spec.Name) {
		t.Errorf("Preflight() error %q does not name the raven", err)
	}
}

// force is the escape hatch from that conflict: the caller has said to replace
// the raven, not adopt it.
func TestClusterApplier_Preflight_ForceAllowsExistingRaven(t *testing.T) {
	t.Parallel()

	spec := wranglerSpec()
	objects := append(preflightObjects(), ravenDeployment(spec.Name, spec.Namespace, 1, 1))

	if err := newClusterApplier(k8sfake.NewSimpleClientset(objects...), nil, testDefaults()).
		Preflight(context.Background(), spec, true); err != nil {
		t.Fatalf("Preflight(force) = %v, want nil", err)
	}
}

// force does not excuse a missing prerequisite: the recreated pod would still
// fail to start.
func TestClusterApplier_Preflight_ForceStillNeedsPrerequisites(t *testing.T) {
	t.Parallel()

	spec := wranglerSpec()
	objects := append(without(preflightObjects(), "ssc"), ravenDeployment(spec.Name, spec.Namespace, 1, 1))

	err := newClusterApplier(k8sfake.NewSimpleClientset(objects...), nil, testDefaults()).
		Preflight(context.Background(), spec, true)
	if err == nil || !strings.Contains(err.Error(), "ssc") {
		t.Errorf("Preflight(force) = %v, want the missing secret reported", err)
	}
}

// Kubernetes accepts a Deployment whose ServiceAccount or mounted Secrets do
// not exist: the request succeeds and the pod never starts. Preflight turns
// that into an error at request time.
func TestClusterApplier_Preflight(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		objects     []runtime.Object
		wantErr     bool
		wantMissing []string
	}{
		{
			name:    "all prerequisites present",
			objects: preflightObjects(),
		},
		{
			// Wrangler only ever provisions into its own namespace, so
			// checking it exists would cost a cluster-scoped RBAC rule.
			name:    "namespace is not checked",
			objects: without(preflightObjects(), "ssg"),
		},
		{
			name:        "missing service account",
			objects:     without(preflightObjects(), "ssg-dev-cleaner"),
			wantErr:     true,
			wantMissing: []string{"ssg-dev-cleaner"},
		},
		{
			name:        "missing mounted secret",
			objects:     without(preflightObjects(), "ssc"),
			wantErr:     true,
			wantMissing: []string{"ssc"},
		},
		{
			name:        "reports every missing prerequisite at once",
			objects:     without(preflightObjects(), "ssg-dev-cleaner", "ssc", "ntrootcert"),
			wantErr:     true,
			wantMissing: []string{"ssg-dev-cleaner", "ssc", "ntrootcert"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			applier := newClusterApplier(k8sfake.NewSimpleClientset(tt.objects...), nil, testDefaults())
			err := applier.Preflight(context.Background(), wranglerSpec(), false)

			if !tt.wantErr {
				if err != nil {
					t.Fatalf("Preflight() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Preflight() = nil, want error")
			}
			for _, want := range tt.wantMissing {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Preflight() error %q does not name missing %q", err, want)
				}
			}
		})
	}
}
