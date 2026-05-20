package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	testclient "k8s.io/client-go/kubernetes/fake"

	"github.com/volck/raven/internal/config"
	"github.com/volck/raven/internal/testutil"
	vaultpkg "github.com/volck/raven/internal/vault"
)

func TestInitKubernetesConfig(t *testing.T) {
	clientset := testclient.NewSimpleClientset()

	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()

	cfg := testutil.NewTestConfig(cluster)
	cfg.DestEnv = "default"
	cfg.Clientset = clientset

	var secretOne = v1.Secret{
		TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "secret", Labels: ApplyRavenLabels()},
	}
	var secretTwo = v1.Secret{
		TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "secrettwo", Labels: ApplyRavenLabels()},
	}
	_, err := clientset.CoreV1().Secrets("default").Create(context.TODO(), &secretOne, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = clientset.CoreV1().Secrets("default").Create(context.TODO(), &secretTwo, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	list, err := KubernetesSecretList(clientset, cfg.DestEnv)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(list.Items))
	}
}

func TestCreatek8sSecretwWithBase64Data(t *testing.T) {
	t.Parallel()
	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client
	cfg := testutil.NewTestConfig(cluster)

	b64DataSecret := map[string]interface{}{
		"data":     map[string]interface{}{"b64secretData": "base64:LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t"},
		"metadata": map[string]interface{}{"version": 2},
	}
	_, err := client.Logical().Write("kv/data/b64data", b64DataSecret)
	if err != nil {
		t.Fatal(err)
	}
	singleSecret := vaultpkg.GetSingleKV(client, "kv", "b64data")
	k8sSecret := CreateK8sSecret("b64data", cfg, singleSecret)
	for _, v := range k8sSecret.Data {
		if strings.Contains(string(v), "base64") {
			t.Fatal("base64 not trimmed")
		}
	}
}

func TestCleanKubernetes(t *testing.T) {
	clientset := testclient.NewSimpleClientset()

	var secretOne = v1.Secret{
		TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "secret", Labels: ApplyRavenLabels()},
	}
	var secretTwo = v1.Secret{
		TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "secrettwo", Labels: ApplyRavenLabels()},
	}

	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	cfg := testutil.NewTestConfig(cluster)
	cfg.DestEnv = "default"
	cfg.Clientset = clientset

	_, _ = clientset.CoreV1().Secrets("default").Create(context.TODO(), &secretOne, metav1.CreateOptions{})
	_, _ = clientset.CoreV1().Secrets("default").Create(context.TODO(), &secretTwo, metav1.CreateOptions{})

	testutil.GenerateTestSecrets(t, client, cfg, "secret")
	testutil.GenerateTestSecrets(t, client, cfg, "secrettwo")

	t.Setenv("KUBERNETESREMOVE", "true")

	k8slistPre, err := KubernetesSecretList(clientset, cfg.DestEnv)
	if err != nil {
		t.Fatal(err)
	}

	picked := []string{"secret"}
	KubernetesRemove(picked, k8slistPre, clientset, cfg.DestEnv)

	k8slistAfter, err := KubernetesSecretList(clientset, cfg.DestEnv)
	if err != nil {
		t.Fatal(err)
	}

	if len(k8slistAfter.Items) >= len(k8slistPre.Items) {
		t.Errorf("secrets were not deleted: pre=%d after=%d", len(k8slistPre.Items), len(k8slistAfter.Items))
	}
}

func TestMonitorForSecret_find_secret(t *testing.T) {
	clientset := testclient.NewSimpleClientset()
	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	cfg := testutil.NewTestConfig(cluster)
	cfg.DestEnv = "default"
	cfg.Clientset = clientset

	var secretOne = v1.Secret{
		TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "secret", Labels: ApplyRavenLabels()},
	}
	var secretTwo = v1.Secret{
		TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "secrettwo", Labels: ApplyRavenLabels()},
	}
	_, _ = clientset.CoreV1().Secrets("default").Create(context.TODO(), &secretOne, metav1.CreateOptions{})
	_, _ = clientset.CoreV1().Secrets("default").Create(context.TODO(), &secretTwo, metav1.CreateOptions{})

	testutil.GenerateTestSecrets(t, client, cfg, "secret")
	testutil.GenerateTestSecrets(t, client, cfg, "secrettwo")

	InitKubernetesSearch("secret", cfg)
}

func TestMonitorForSecret_ShouldExpire(t *testing.T) {
	clientset := testclient.NewSimpleClientset()
	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	cfg := testutil.NewTestConfig(cluster)
	cfg.DestEnv = "default"
	cfg.Clientset = clientset

	testutil.GenerateTestSecrets(t, client, cfg, "secret")
	testutil.GenerateTestSecrets(t, client, cfg, "secrettwo")

	InitKubernetesSearch("secret", cfg)
}

func TestWatcher_MonitorNamespaceForSecretChange(t *testing.T) {
	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client
	cfg := testutil.NewTestConfig(cluster)

	theLogger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	newClient := testclient.NewSimpleClientset()

	w := NewWatcher(theLogger, newClient, cfg.DestEnv)
	go w.MonitorNamespaceForSecretChange()

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "test-deployment", Namespace: cfg.DestEnv},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "test-app"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      map[string]string{"app": "test-app"},
					Annotations: map[string]string{},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "test-container", Image: "your-image",
						Ports:        []corev1.ContainerPort{{ContainerPort: 80}},
						VolumeMounts: []corev1.VolumeMount{{Name: "secret-volume", MountPath: "/etc/secret-volume", ReadOnly: true}},
					}},
					Volumes: []corev1.Volume{{
						Name:         "secret-volume",
						VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "secret"}},
					}},
				},
			},
		},
	}

	statefulSet := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "test-statefulset", Namespace: cfg.DestEnv},
		Spec: appsv1.StatefulSetSpec{
			ServiceName: "test-service",
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "test-app"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "test-app"}},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "test-container", Image: "your-image",
						Ports:        []corev1.ContainerPort{{ContainerPort: 80}},
						VolumeMounts: []corev1.VolumeMount{{Name: "secret-volume", MountPath: "/etc/secret-volume", ReadOnly: true}},
					}},
					Volumes: []corev1.Volume{{
						Name:         "secret-volume",
						VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "secret"}},
					}},
				},
			},
		},
	}

	_, err := newClient.AppsV1().StatefulSets(cfg.DestEnv).Create(context.Background(), statefulSet, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("could not create statefulset: %v", err)
	}
	_, err = newClient.AppsV1().Deployments(cfg.DestEnv).Create(context.TODO(), deployment, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("could not create deployment: %v", err)
	}

	secrets := map[string]interface{}{
		"data":     map[string]interface{}{"secretKey": "secretValue"},
		"metadata": map[string]interface{}{"version": 2},
	}
	_, err = client.Logical().Write("kv/data/secret", secrets)
	if err != nil {
		t.Fatal(err)
	}

	singleSecret := vaultpkg.GetSingleKV(client, "kv", "secret")
	k8sSecret := CreateK8sSecret("secret", cfg, singleSecret)
	if k8sSecret.Data == nil && k8sSecret.StringData == nil {
		t.Fatal("k8sSecret nil, data not loaded")
	}

	_, err = newClient.CoreV1().Secrets(cfg.DestEnv).Create(context.Background(), &k8sSecret, metav1.CreateOptions{})
	if err != nil {
		fmt.Println(err)
	}
	_, err = newClient.CoreV1().Secrets(cfg.DestEnv).Update(context.Background(), &k8sSecret, metav1.UpdateOptions{})
	if err != nil {
		fmt.Println(err)
	}
}

func Test_applyMetadata(t *testing.T) {
	testCases := []struct {
		name            string
		secretName      string
		customInputData map[string]interface{}
		want            map[string]string
	}{
		{
			name:       "Test with AWS ARN",
			secretName: "custom_metadataSecret",
			customInputData: map[string]interface{}{
				"AWS_ARN_REF": "arn:aws:iam::123456789012:role/role-name",
			},
			want: map[string]string{
				"AWS_ARN_REF": "arn:aws:iam::123456789012:role/role-name",
			},
		},
		{
			name:       "NO_SYNC option enabled",
			secretName: "custom_metadataSecret",
			customInputData: map[string]interface{}{
				"NO_SYNC": "true",
			},
			want: map[string]string{
				"NO_SYNC": "true",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cluster := testutil.CreateVaultTestCluster(t)
			defer cluster.Cleanup()
			client := cluster.Cores[0].Client
			cfg := testutil.NewTestConfig(cluster)

			dataFields := generateCustomMetadataSecret(t, client, cfg, tc.secretName, tc.customInputData)
			annotations := ApplyAnnotations(dataFields, cfg)
			got := ApplyMetadata(dataFields, annotations)
			if tc.name == "Test with AWS ARN" {
				if got["AWS_ARN_REF"] != tc.want["AWS_ARN_REF"] {
					t.Fatalf("expected AWS_ARN_REF=%s, got=%s", tc.want["AWS_ARN_REF"], got["AWS_ARN_REF"])
				}
			} else if tc.name == "NO_SYNC option enabled" {
				if got["NO_SYNC"] != tc.want["NO_SYNC"] {
					t.Fatalf("expected NO_SYNC=%s, got=%s", tc.want["NO_SYNC"], got["NO_SYNC"])
				}
			}
		})
	}
}

func generateCustomMetadataSecret(t *testing.T, client *api.Client, cfg config.Config, secretName string, customInputData map[string]interface{}) *api.Secret {
	t.Helper()

	customMetadata := customInputData
	if customMetadata == nil {
		customMetadata = map[string]interface{}{}
	}

	secretData := map[string]interface{}{
		"data": map[string]interface{}{
			"secretKey": "secretValue2",
		},
		"custom_metadata": customMetadata,
	}

	writePath := fmt.Sprintf("%s/metadata/%s", cfg.SecretEngine, secretName)
	_, err := client.Logical().Write(writePath, secretData)
	if err != nil {
		t.Fatal(err)
	}

	writeDataPath := fmt.Sprintf("%s/data/%s", cfg.SecretEngine, secretName)
	_, err = client.Logical().Write(writeDataPath, secretData)
	if err != nil {
		t.Fatal(err)
	}

	secret, err := client.Logical().Read(writeDataPath)
	if err != nil {
		t.Fatal(err)
	}

	return secret
}
