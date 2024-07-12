package main

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	testclient "k8s.io/client-go/kubernetes/fake"
	"log/slog"
	"os"
	"strings"
	"testing"
)

func TestCreatek8sSecret(t *testing.T) {
	tests := []struct {
		name     string
		secrets  map[string]interface{}
		wantData bool
	}{
		{
			name:     "Test with missing data field",
			secrets:  map[string]interface{}{"data": nil, "metadata": nil},
			wantData: false,
		},
		{
			name: "Test with valid data",
			secrets: map[string]interface{}{
				"data":     map[string]interface{}{"secretKey": "secretValue"},
				"metadata": map[string]interface{}{"version": 2},
			},
			wantData: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cluster := createVaultTestCluster(t)
			defer cluster.Cleanup()
			client := cluster.Cores[0].Client
			config := config{
				vaultEndpoint: cluster.Cores[0].Client.Address(),
				secretEngine:  "kv",
				token:         client.Token(),
				destEnv:       "kv",
			}

			_, err := client.Logical().Write("kv/data/secret", tt.secrets)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Could not get list of secrets for kubernetes namespace")
			}
			singleSecret := getSingleKV(client, "kv", "secret")
			fmt.Println(singleSecret.Data["metadata"].(map[string]interface{})["custom_metadata"])
			k8sSecret := createK8sSecret("secret", config, singleSecret)

			fmt.Println(k8sSecret.Annotations)

			if tt.wantData && (k8sSecret.Data == nil && k8sSecret.StringData == nil) {
				t.Fatal("k8sSecret nil, data not loaded")
			}

			if !tt.wantData && (k8sSecret.Data != nil || k8sSecret.StringData != nil) {
				t.Fatal("k8sSecret not nil, data loaded unexpectedly")
			}
		})
	}
}

func TestInitKubernetesConfig(t *testing.T) {
	Clientset := testclient.NewSimpleClientset()

	cluster := createVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	config := config{
		vaultEndpoint: cluster.Cores[0].Client.Address(),
		secretEngine:  "kv",
		token:         client.Token(),
		destEnv:       "default",
		pemFile:       "cert.pem",
		Clientset:     Clientset,
	}

	metaforone := metav1.TypeMeta{
		Kind:       "Secret",
		APIVersion: "v1",
	}
	objectmetaforone := metav1.ObjectMeta{
		Name:   "secret",
		Labels: applyRavenLabels(),
	}

	metafortwo := metav1.TypeMeta{
		Kind:       "Secret",
		APIVersion: "v1",
	}
	objectmetafortwo := metav1.ObjectMeta{
		Name:   "secrettwo",
		Labels: applyRavenLabels(),
	}

	var secretOne = v1.Secret{
		TypeMeta:   metaforone,
		ObjectMeta: objectmetaforone,
	}
	var secretTwo = v1.Secret{
		TypeMeta:   metafortwo,
		ObjectMeta: objectmetafortwo,
		Immutable:  nil,
		Data:       nil,
		StringData: nil,
		Type:       "",
	}
	_, err := Clientset.CoreV1().Secrets("default").Create(context.TODO(), &secretOne, metav1.CreateOptions{})
	if err != nil {
		fmt.Println("testing failed, err", err)
	}
	_, err = Clientset.CoreV1().Secrets("default").Create(context.TODO(), &secretTwo, metav1.CreateOptions{})
	if err != nil {
		fmt.Println("testing failed, err", err)
	}

	fmt.Println(kubernetesSecretList(Clientset, config.destEnv))

}

func TestCreatek8sSecretwWithBase64Data(t *testing.T) {
	// init client
	t.Parallel()
	cluster := createVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client
	config := config{
		vaultEndpoint: cluster.Cores[0].Client.Address(),
		secretEngine:  "kv",
		token:         client.Token(),
		destEnv:       "kv",
	}
	//create base64Datasecret
	b64DataSecret := map[string]interface{}{
		"data": map[string]interface{}{"b64secretData": `base64:LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZWekNDQXorZ0F3SUJBZ0lKQU9MTEw2V2Va
b0VrTUEwR0NTcUdTSWIzRFFFQkN3VUFNRUl4Q3pBSkJnTlYKQkFZVEFsaFlNUlV3RXdZRFZRUUhE
QXhFWldaaGRXeDBJRU5wZEhreEhEQWFCZ05WQkFvTUUwUmxabUYxYkhRZwpRMjl0Y0dGdWVTQk1k
R1F3SGhjTk1qRXdOekF4TURVek16UXpXaGNOTWpJd056QXhNRFV6TXpReldqQkNNUXN3CkNRWURW
UVFHRXdKWVdERVZNQk1HQTFVRUJ3d01SR1ZtWVhWc2RDQkRhWFI1TVJ3d0dnWURWUVFLREJORVpX
WmgKZFd4MElFTnZiWEJoYm5rZ1RIUmtNSUlDSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQWc4QU1J
SUNDZ0tDQWdFQQp0bGpEVEhibkJ0NlNJcDBRMW01RC9tbW9MdnJoeWJRRDFBa1VHTDVrSjhZcmdZ
OG5JSjM2bWRxemhma3dlcVViCkRPUzhOcEpzcHhjdlgyZWlRS1k5TWM1Vm9xa25FMC9lM1doRWdK
RndYYmRqREppdUlLNS8vcjFPM1NpKzArSWUKRUo1WWx3OWFYR0lJOWs0V1d0REFMMktlY1JrNWc5
VFlmTzdwRjd4TGRjUlhCcWNIbCszbUxDVnFQYXFpNEY3bgpnVDhwRjBtOG9HOHdCMXNvNzN1RFlt
NkRJd0VTVk55VytBL21oMGRZbk8rTHZaVURCb1pFaUcxMUdXTDY1bzBXClJwejZ1STYwRTR0NEVP
ZEt1UFBwM0FueHVHWnk5TzlZTWdJVHpUQjFSazJOOGxPT25jRzZtanRTN0cyZFRhOEMKVVJxc2pu
RldxZEpLRHNsTFhhWk05eEo3d3pVeStpaE5SKy91UEZKSXpEVXlFMVRNQjZGSDdLcysrQ0lzTm9N
VwpydFN4ckM4MlZ2UTdVSkViaGJ5azRqNXhWSzhWYk43M0dJOXNwN21mR0dBQnJKT2RkYTU5R0Yx
bUJHYllsMHdWCndvY2lIanozWjhMWXZKNXpCQjNSS1JGT1NGUXc3RTI3QzR0dXNXNTk3T2Z5MCta
R0VqQnR0QTZwV25BZjMzZ2sKTVVQMTYwczdTTGJ1dUNER2l2VmhDNlhkMDBJbTh0NGFmRUwxYmx6
M2tWd3pKR1ZMME94OFlSaUpROUY5czYycwpvRHdJNERPWHN5dTV2dUkxRmVXSVRRendxdnpXZjJR
VkM3NmVyR21xa00zcFdnUURtVHoyalNzbCt3ZS9BK1dCCmtUY0RiYXFuVWN6d0RUM2pMeXRleFVR
KzFpcUIxb3VjeXA0UUk5RnJ3ajhDQXdFQUFhTlFNRTR3SFFZRFZSME8KQkJZRUZPamk5SWJIVzFx
VFEwWHFyQlBHLzY2MlBJYkFNQjhHQTFVZEl3UVlNQmFBRk9qaTlJYkhXMXFUUTBYcQpyQlBHLzY2
MlBJYkFNQXdHQTFVZEV3UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dJQkFDdXQvVmMw
CktLK0tPQ0xNU0JxbnFzaUppZW1FdUpEYXlKMFp3akpQT3JjSXJtY1FvcTdJODJDZ1pEeEMvK3Uy
aXVLc0JzU2oKMHF1aWpLRVhvcDg2QjkwZWFBVjUwcXRtZHpiNW84YTdwTFF2MmxHUGhreHVVcTR6
Ylk4Rkx4ZmhmMnBhQk5YTgpHM0ZPZU9wMkgxSWJkSWZyOVptL0x1UjkwQmJ3Mmh3SkVKSFNiTjZl
STE3ZFJwaVBFdlVuY09kS0M5Z1dFdVd2CjVNMkU5c1creS9TOU1LSEdkSWJCNjBLMjA1WjZrS1hx
ckNnWlg5Q1NNc3YwUDNoaFVqQmFCQWtmV0hQUU9BdVUKSG5yb2J5UG9kMmltN1RwZXdMZ1VvM1V5
UlVXT2lxdjNaMjZpZnZLNS8xNzJKaHFBRVpTTFQ3N095YkZIdzdPMApLc1VCVlBlQ3huWlhQNGlx
eWhYNHRoMkpXUHljaXlqTXB4TzhSd3hYKzBhVnErZnJYZmNrM0laalRqOSt4blI2Cld5RnlGVVZP
Z2VhOElzRXZReVo5WllOUVJKYWxkYnhZb0N5eGs1NFYydTdIdDUyU2hJWEtaam5INms3YVBTa2MK
c1FuUEc0THJRell3K3d1REtPTDZNZXpSbURsYzhvaHo5MVZrem9JVytxcXY5VTBUS3hjWCtGN01X
YkJCNjBoQgpVcVJoejVzY2Zmem5pdUJqNHJzdkcvQlRlR2NFVnZzSVZwRE5oRmF2OFNUaWYzNVB0
L1drYUxSaTh4OWVObElXCmRQZTc2anNVVHFMeTBDeVVtSDZDWk5ObTVKUVlIRzlBd3hUUkJiMCtU
Ri9YQklaeCtFU1VOcUlDR0JrV0hvNDUKZEpGM0UvN09NellDT1hEQ3lNR1lQZzBMQlJGNEJBM2tW
emxMCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K
`},
		"metadata": map[string]interface{}{"version": 2},
	}
	// write testobject
	_, err := client.Logical().Write("kv/data/b64data", b64DataSecret)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("client.Logical().Write(\"kv/data/b64data\", b64DataSecret)")

	}
	singleSecret := getSingleKV(client, "kv", "b64data")
	k8sSecret := createK8sSecret("b64data", config, singleSecret)
	for _, v := range k8sSecret.Data {
		if strings.Contains(string(v), "base64") {
			t.Fatal("base64 not trimmed")
		}

	}

}

func TestCleanKubernetes(t *testing.T) {
	Clientset := testclient.NewSimpleClientset()
	metaforone := metav1.TypeMeta{
		Kind:       "Secret",
		APIVersion: "v1",
	}
	objectmetaforone := metav1.ObjectMeta{
		Name:   "secret",
		Labels: applyRavenLabels(),
	}

	metafortwo := metav1.TypeMeta{
		Kind:       "Secret",
		APIVersion: "v1",
	}
	objectmetafortwo := metav1.ObjectMeta{
		Name:   "secrettwo",
		Labels: applyRavenLabels(),
	}

	var secretOne = v1.Secret{
		TypeMeta:   metaforone,
		ObjectMeta: objectmetaforone,
	}
	var secretTwo = v1.Secret{
		TypeMeta:   metafortwo,
		ObjectMeta: objectmetafortwo,
		Immutable:  nil,
		Data:       nil,
		StringData: nil,
		Type:       "",
	}
	cluster := createVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	config := config{
		vaultEndpoint: cluster.Cores[0].Client.Address(),
		secretEngine:  "kv",
		token:         client.Token(),
		destEnv:       "default",
		pemFile:       "cert.pem",
		Clientset:     Clientset,
	}

	_, err := config.Clientset.CoreV1().Secrets("default").Create(context.TODO(), &secretOne, metav1.CreateOptions{})
	if err != nil {
		fmt.Println("testing failed, err", err)
	}
	_, err = config.Clientset.CoreV1().Secrets("default").Create(context.TODO(), &secretTwo, metav1.CreateOptions{})
	if err != nil {
		fmt.Println("testing failed, err", err)
	}

	secretName := "secret"
	secretNameTwo := "secrettwo"
	generateTestSecrets(t, client, config, secretName)
	generateTestSecrets(t, client, config, secretNameTwo)

	PreviousKV, err := getAllKVs(client, config)
	if err != nil {
		fmt.Println(err)
	}
	previousKV := PreviousKV.Data["keys"].([]interface{})
	persistVaultChanges(previousKV, client, config)
	previouskvlst := mySecretList
	deleteTestSecrets(t, client, config, secretName)

	newKV, err := getAllKVs(client, config)
	if err != nil {
		fmt.Println(err)
	}
	newkvlst := newKV.Data["keys"].([]interface{})
	persistVaultChanges(newkvlst, client, config)
	picked := PickRipeSecrets(previouskvlst, mySecretList)
	fmt.Println(picked, len(picked))

	k8slistPre, err := kubernetesSecretList(Clientset, config.destEnv)
	if err != nil {
		fmt.Println("k8slist error", err)
	}

	kubernetesRemove(picked, k8slistPre, Clientset, config.destEnv)

	k8slistAfter, err := kubernetesSecretList(Clientset, config.destEnv)

	if k8slistPre == k8slistAfter {
		fmt.Printf("pre: %v\n after: %v\n", k8slistPre, k8slistAfter)
		t.Error("there is no difference between cluster snapshots. i.e. secrets were not deleted")
	} else {
		fmt.Printf("pre: %v\n after: %v\n. list should not match", k8slistPre.Items, k8slistAfter.Items)
	}

}

func TestMonitorForSecret_find_secret(t *testing.T) {

	Clientset := testclient.NewSimpleClientset()
	metaforone := metav1.TypeMeta{
		Kind:       "Secret",
		APIVersion: "v1",
	}
	objectmetaforone := metav1.ObjectMeta{
		Name:   "secret",
		Labels: applyRavenLabels(),
	}

	metafortwo := metav1.TypeMeta{
		Kind:       "Secret",
		APIVersion: "v1",
	}
	objectmetafortwo := metav1.ObjectMeta{
		Name:   "secrettwo",
		Labels: applyRavenLabels(),
	}

	var secretOne = v1.Secret{
		TypeMeta:   metaforone,
		ObjectMeta: objectmetaforone,
	}
	var secretTwo = v1.Secret{
		TypeMeta:   metafortwo,
		ObjectMeta: objectmetafortwo,
		Immutable:  nil,
		Data:       nil,
		StringData: nil,
		Type:       "",
	}
	_, err := Clientset.CoreV1().Secrets("default").Create(context.TODO(), &secretOne, metav1.CreateOptions{})
	if err != nil {
		fmt.Println("testing failed, err", err)
	}
	_, err = Clientset.CoreV1().Secrets("default").Create(context.TODO(), &secretTwo, metav1.CreateOptions{})
	if err != nil {
		fmt.Println("testing failed, err", err)
	}

	cluster := createVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	config := config{
		vaultEndpoint: cluster.Cores[0].Client.Address(),
		secretEngine:  "kv",
		token:         client.Token(),
		destEnv:       "default",
		pemFile:       "cert.pem",
		Clientset:     Clientset,
	}

	secretName := "secret"
	secretNameTwo := "secrettwo"
	generateTestSecrets(t, client, config, secretName)
	generateTestSecrets(t, client, config, secretNameTwo)

	initKubernetesSearch(secretName, config)
}

func TestMonitorForSecret_ShouldExpire(t *testing.T) {

	Clientset := testclient.NewSimpleClientset()

	cluster := createVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	config := config{
		vaultEndpoint: cluster.Cores[0].Client.Address(),
		secretEngine:  "kv",
		token:         client.Token(),
		destEnv:       "default",
		pemFile:       "cert.pem",
		Clientset:     Clientset,
	}

	secretName := "secret"
	secretNameTwo := "secrettwo"
	generateTestSecrets(t, client, config, secretName)
	generateTestSecrets(t, client, config, secretNameTwo)

	initKubernetesSearch(secretName, config)

}

func TestWatcher_MonitorNamespaceForSecretChange(t *testing.T) {

	cluster := createVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client
	c := config{
		vaultEndpoint: cluster.Cores[0].Client.Address(),
		secretEngine:  "kv",
		token:         client.Token(),
		destEnv:       "kv",
	}

	theLogger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	newClient := testclient.NewSimpleClientset()

	w := NewWatcher(theLogger, newClient, c.destEnv)
	go w.MonitorNamespaceForSecretChange()

	// Define the deployment
	deploymentName := "test-deployment"
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deploymentName,
			Namespace: c.destEnv,
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "test-app",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "test-app",
					},
					Annotations: map[string]string{},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "test-container",
							Image: "your-image",
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: 80,
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "secret-volume",
									MountPath: "/etc/secret-volume",
									ReadOnly:  true,
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "secret-volume",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: "secret",
								},
							},
						},
					},
				},
			},
		},
	}
	statefulSetName := "test-statefulset"

	statefulSet := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      statefulSetName,
			Namespace: c.destEnv,
		},
		Spec: appsv1.StatefulSetSpec{
			ServiceName: "test-service",
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "test-app",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "test-app",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "test-container",
							Image: "your-image",
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: 80,
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "secret-volume",
									MountPath: "/etc/secret-volume",
									ReadOnly:  true,
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "secret-volume",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: "secret",
								},
							},
						},
					},
				},
			},
		},
	}

	_, err := newClient.AppsV1().StatefulSets(c.destEnv).Create(context.Background(), statefulSet, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("could not create statefulset: %v", err)
	}
	// Create the deployment
	_, err = newClient.AppsV1().Deployments(c.destEnv).Create(context.TODO(), deployment, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("could not create deployment: %v", err)

	}

	// make testable secrets for cluster
	secrets := map[string]interface{}{
		"data":     map[string]interface{}{"secretKey": "secretValue"},
		"metadata": map[string]interface{}{"version": 2},
	}
	_, err = client.Logical().Write("kv/data/secret", secrets)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Could not get list of secrets for kubernetes namespace")
	}

	//w.MonitorNamespaceForSecretChange()
	singleSecret := getSingleKV(client, "kv", "secret")
	k8sSecret := createK8sSecret("secret", c, singleSecret)
	if k8sSecret.Data == nil && k8sSecret.StringData == nil {
		t.Fatal("k8sSecret nil, data not loaded")
	}
	w.Logger.Info("labels", slog.String("labels", k8sSecret.ObjectMeta.Labels["managedBy"]))
	_, err = newClient.CoreV1().Secrets(c.destEnv).Create(context.Background(), &k8sSecret, metav1.CreateOptions{})
	if err != nil {
		fmt.Println(err)
	}

	_, err = newClient.CoreV1().Secrets(c.destEnv).Update(context.Background(), &k8sSecret, metav1.UpdateOptions{})
	if err != nil {
		fmt.Println(err)
	}

}

func TestCreateK8sSecretWithCustomMetadata(t *testing.T) {
	tests := []struct {
		name     string
		secrets  map[string]interface{}
		wantData bool
	}{
		{
			name:     "Test with missing data field",
			secrets:  map[string]interface{}{"data": nil, "metadata": nil},
			wantData: false,
		},
		{
			name: "Test with valid data",
			secrets: map[string]interface{}{
				"data":     map[string]interface{}{"secretKey": "secretValue"},
				"metadata": map[string]interface{}{"version": 2, "custom_metadata": map[string]interface{}{"my_data": "very_custom"}},
			},
			wantData: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cluster := createVaultTestCluster(t)
			defer cluster.Cleanup()
			client := cluster.Cores[0].Client
			config := config{
				vaultEndpoint: cluster.Cores[0].Client.Address(),
				secretEngine:  "kv",
				token:         client.Token(),
				destEnv:       "kv",
			}

			GenerateCustomMetadataSecret(t, client, config, "secret", nil)

			singleSecret := getSingleKV(client, config.secretEngine, "secret")
			fmt.Println(singleSecret.Data["metadata"].(map[string]interface{})["custom_metadata"])

			k8sSecret := createK8sSecret("secret", config, singleSecret)

			fmt.Println(k8sSecret)

			if tt.wantData && (k8sSecret.Data == nil && k8sSecret.StringData == nil) {
				t.Fatal("k8sSecret nil, data not loaded")
			}

			if !tt.wantData && (k8sSecret.Data != nil || k8sSecret.StringData != nil) {
				t.Fatal("k8sSecret not nil, data loaded unexpectedly")
			}
		})
	}
}

func TestApplyMetadata(t *testing.T) {
	// Define the test cases

	cluster := createVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client
	config := config{
		vaultEndpoint: cluster.Cores[0].Client.Address(),
		secretEngine:  "kv",
		token:         client.Token(),
		destEnv:       "kv",
	}

	GenerateCustomMetadataSecret(t, client, config, "secret", nil)

	singleSecret := getSingleKV(client, "kv", "secret")
	fmt.Println(singleSecret.Data["metadata"].(map[string]interface{})["custom_metadata"])
	k8sSecret := createK8sSecret("secret", config, singleSecret)
	fmt.Println(k8sSecret.Annotations)

}

func Test_applyMetadata(t *testing.T) {
	// Define the test cases
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
		// Add more test cases as needed
	}

	// startRaven the test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cluster := createVaultTestCluster(t)
			defer cluster.Cleanup()
			client := cluster.Cores[0].Client
			config := config{
				vaultEndpoint: cluster.Cores[0].Client.Address(),
				secretEngine:  "kv",
				token:         client.Token(),
				destEnv:       "kv",
				pemFile:       "cert.pem",
			}

			dataFields := GenerateCustomMetadataSecret(t, client, config, tc.secretName, tc.customInputData)
			Annotations := applyAnnotations(dataFields, config)
			got := applyMetadata(dataFields, Annotations)
			if tc.name == "Test with AWS ARN" {
				if got["AWS_ARN_REF"] != tc.want["AWS_ARN_REF"] {
					t.Fatal()
				} else {
					fmt.Printf("Test passed, got %v", got["AWS_ARN_REF"])
				}
			} else if tc.name == "NO_SYNC option enabled" {
				if got["NO_SYNC"] != tc.want["NO_SYNC"] {
					t.Fatal()
				} else {
					fmt.Printf("Test passed, got NO_SYNC %v", got["NO_SYNC"])
				}
			}
		})
	}
}
