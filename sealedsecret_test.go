package main

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"os"
	"reflect"
	"testing"
)

func CompareSealedAndK8sSecrets(t *testing.T, UnsealedSecret *v1.Secret, k8sSecret v1.Secret) (valid bool) {
	for UnsealedSecretKey, UnsealedSecretValue := range UnsealedSecret.Data {
		for k8sKey, k8sValue := range k8sSecret.StringData {
			if UnsealedSecretKey == k8sKey && k8sValue == string(UnsealedSecretValue) {
				valid = true
				fmt.Printf("found valid field: %s and valid key %s ", UnsealedSecretKey, UnsealedSecretValue)
			}
		}
	}
	return valid
}

func TestSealedSecretMatchk8sSecret(t *testing.T) {
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

	secretName := "secret"

	generateTestSecrets(t, client, config, secretName)
	//we need to unseal sealedsecret and compare it to a k8sSecret
	SealedSecret, k8sSecret := ReadConvertKVFromVault(t, client, config.secretEngine, secretName, config.destEnv, config.pemFile)
	var codecs serializer.CodecFactory

	privateKeys := ReturnPrivateKey(t)

	UnsealedSecret := UnsealSecretAndReturn(t, SealedSecret, codecs, privateKeys)
	if !CompareSealedAndK8sSecrets(t, UnsealedSecret, k8sSecret) {
		t.Fatal("verifying failed")
	}

}

func TestGetKVAndCreateNormalSealedSecret(t *testing.T) {
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
	// make testable secrets for cluster
	secrets := map[string]interface{}{
		"data":     map[string]interface{}{"secretKey": "secretValue"},
		"metadata": map[string]interface{}{"version": 2},
	}
	client.Logical().Write("kv/data/secret", secrets)

	secretEngine := "kv"
	secretName := "secret"
	pemFile := `cert.crt`
	// SingleKVFromVault := getSingleKV(client, secretEngine, secretName)
	input := fmt.Sprintf("%s/%s", secretEngine, secretName)
	kvVaultList := iterateList(input, client, "")
	fmt.Println("kvVaultList", kvVaultList)
	k8sSecret := createK8sSecret(secretName, config, kvVaultList)
	fmt.Println("we created a k8ssecret called", k8sSecret.Name, k8sSecret)
	SealedSecret := createSealedSecret(pemFile, &k8sSecret)
	fmt.Println("we converted that k8ssecret to a sealedSecret", SealedSecret.Name, SealedSecret)
	fmt.Printf("k8sSecret.Data: %v \n k8sSecret.StringData: %v \n k8sSecret.Annotations: %v \n", k8sSecret.Data, k8sSecret.StringData, k8sSecret.Annotations)
	fmt.Printf("SealedSecret: %v \n SealedSecret.Annotations: %v \n", SealedSecret, k8sSecret.Annotations)

}

func TestCreateThreeSealedSecrets(t *testing.T) {

	t.Parallel()

	cluster := createVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client
	config := config{
		vaultEndpoint: cluster.Cores[0].Client.Address(),
		secretEngine:  "kv",
		token:         client.Token(),
		destEnv:       "kv",
		pemFile:       "cert.crt",
	}
	// make testable secrets for cluster
	secretOne := map[string]interface{}{
		"data":     map[string]interface{}{"SecretOne": "secretValue"},
		"metadata": map[string]interface{}{"version": 2},
	}
	secretTwo := map[string]interface{}{
		"data":     map[string]interface{}{"secretTwo": "secretValue"},
		"metadata": map[string]interface{}{"version": 2},
	}
	secretThree := map[string]interface{}{
		"data":     map[string]interface{}{"secretThree": "secretValue"},
		"metadata": map[string]interface{}{"version": 2},
	}
	secretThreev2 := map[string]interface{}{
		"data":     map[string]interface{}{"secretThreev2": "secretValue"},
		"metadata": map[string]interface{}{"version": 2},
	}

	firstPath := "kv/data/subpathone"
	secondPath := "kv/data/subpathone/secretSecondPath"
	thirdPath := "kv/data/subpathone/subpathtwo/secretThirdPath"
	thirdPathv2 := "kv/data/subpathone/subpathtwo/secretThirdPathV2"
	client.Logical().Write(firstPath, secretOne)
	client.Logical().Write(secondPath, secretTwo)
	client.Logical().Write(thirdPath, secretThree)
	client.Logical().Write(thirdPathv2, secretThreev2)

	list, err := getAllKVs(client, config)
	if err != nil {
		fmt.Println(err)
	}
	secretList := list.Data["keys"].([]interface{})

	synchronizeVaultSecrets(secretList, client, config)
}

func TestGetKVAndCreateNormalSealedSecretWithNoDataFields(t *testing.T) {
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
	// make testable secrets for cluster
	secrets := map[string]interface{}{
		"data":     nil,
		"metadata": map[string]interface{}{"version": 2},
	}
	client.Logical().Write("kv/data/secret", secrets)

	secretEngine := "kv"
	secretName := "secret"
	pemFile := `cert.crt`

	SingleKVFromVault := getSingleKV(client, secretEngine, secretName)
	k8sSecret := createK8sSecret(secretName, config, SingleKVFromVault)
	SealedSecret := createSealedSecret(pemFile, &k8sSecret)
	fmt.Printf("k8sSecret.Data: %v \n k8sSecret.StringData: %v \n k8sSecret.Annotations: %v \n", k8sSecret.Data, k8sSecret.StringData, k8sSecret.Annotations)
	fmt.Printf("SealedSecret: %v \n SealedSecret.Annotations: %v \n", SealedSecret, k8sSecret.Annotations)

}

func TestGetKVAndCreateSealedSecretWithDocumentKeysAnnotations(t *testing.T) {
	t.Parallel()
	// Initiate cluster and get client
	cluster := createVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client
	config := config{
		vaultEndpoint: cluster.Cores[0].Client.Address(),
		secretEngine:  "kv",
		token:         client.Token(),
		destEnv:       "kv",
	}

	secrets := map[string]interface{}{
		"data":     map[string]interface{}{"totallyDifferent": "secretValue", "raven/description": "some very secret secret that we need to use to make world go around"},
		"metadata": map[string]interface{}{"version": 2},
	}
	//make secret with raven/description field to see if DocumentKeys are working

	client.Logical().Write("kv/data/DocumentKeyAnnotation", secrets)

	secretEngine := "kv"
	secretName := "DocumentKeyAnnotation"
	pemFile := `cert.crt`

	SingleKVFromVault := getSingleKV(client, secretEngine, secretName)
	k8sSecret := createK8sSecret(secretName, config, SingleKVFromVault)
	SealedSecret := createSealedSecret(pemFile, &k8sSecret)
	seen := false

	//iterate keys to see if documentKeys are present
	for keySealedSecret, _ := range SealedSecret.Annotations {
		for i := range newConfig.DocumentationKeys {
			if newConfig.DocumentationKeys[i] == keySealedSecret {
				seen = true
				fmt.Printf("DocumentationKey(%s) seen here, present in sealed secret as annotation \n", keySealedSecret)
			}
		}
	}
	if !seen {
		t.Fatal("TestGetKVAndCreateSealedSecretWithDocumentKeysAnnotations failed. Seen:", seen)
	}

}

func TestCompareThatSealedSecretAndSecretMetadataMatches(t *testing.T) {
	t.Parallel()
	// Initiate cluster and get client
	cluster := createVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client
	config := config{
		vaultEndpoint: cluster.Cores[0].Client.Address(),
		secretEngine:  "kv",
		token:         client.Token(),
		destEnv:       "kv",
	}

	secrets := map[string]interface{}{
		"data":     map[string]interface{}{"totallyDifferent": "secretValue", "raven/description": "some very secret secret that we need to use to make world go around"},
		"metadata": map[string]interface{}{"version": 2},
	}
	//make secret with raven/description field to see if DocumentKeys are working

	client.Logical().Write("kv/data/TestCompareThatSealedSecretAndSecretMetadataMatches", secrets)

	secretEngine := "kv"
	secretName := "TestCompareThatSealedSecretAndSecretMetadataMatches"
	pemFile := `cert.crt`

	SingleKVFromVault := getSingleKV(client, secretEngine, secretName)
	k8sSecret := createK8sSecret(secretName, config, SingleKVFromVault)
	SealedSecret := createSealedSecret(pemFile, &k8sSecret)
	if !reflect.DeepEqual(k8sSecret.TypeMeta, SealedSecret.TypeMeta) {
		t.Fatal("TestCompareThatSealedSecretAndSecretMetadataMatches TypeMeta neq")
	} else if !reflect.DeepEqual(k8sSecret.Annotations, k8sSecret.Annotations) {
		t.Fatal("TestCompareThatSealedSecretAndSecretMetadataMatches Annotations neq")
	}
	fmt.Printf("k8s: %v \n sealed: %v \n", k8sSecret, SealedSecret)
	fmt.Printf("sealedsecret.name: %v \n k8s.name: %v \n", SealedSecret.Name, k8sSecret.Name)

}

func Test_listsMatchNillist(t *testing.T) {
	PreviousKV := map[string]*api.Secret{}
	NewKV := map[string]*api.Secret{}
	if !listsMatch(PreviousKV, NewKV) {
		t.Fatal("listsMatchNillist does not match list. lists are the exact same object and should match")
	}
}

func Test_listsMatchDiff(t *testing.T) {
	PreviousKV := map[string]*api.Secret{}

	data := make(map[string]interface{})
	data["mysecret"] = "123"

	previousSecret := &api.Secret{
		RequestID:     "",
		LeaseID:       "",
		LeaseDuration: 0,
		Renewable:     false,
		Data:          data,
		Warnings:      nil,
		Auth:          nil,
		WrapInfo:      nil,
	}
	NewKV := map[string]*api.Secret{}
	PreviousKV["theSecret"] = previousSecret
	if listsMatch(PreviousKV, NewKV) {
		t.Fatal("listsMatchDiff should have differences. ")
	}

}

func TestReadSealedSecretAndCompareWithVaultStruct(t *testing.T) {
	tests := []struct {
		name        string
		kv          *api.Secret
		fileContent string
		filePointer string
		engine      string
		expected    bool
	}{
		{
			name: "NoUpdateNeeded",
			kv: &api.Secret{
				Data: map[string]interface{}{
					"metadata": map[string]interface{}{
						"created_time": "2023-10-01T00:00:00Z",
					},
				},
			},
			fileContent: `
metadata:
  annotations:
    created_time: "2023-10-01T00:00:00Z"
    source: "test-engine"
`,
			filePointer: "test-sealed-secret.yaml",
			engine:      "test-engine",
			expected:    false,
		},
		{
			name: "NoUpdateNeeded",
			kv: &api.Secret{
				Data: map[string]interface{}{
					"metadata": map[string]interface{}{
						"created_time": "2023-10-01T00:00:00Z",
					},
				},
			},
			fileContent: `
metadata:
  annotations:
    created_time: "2023-10-01T00:00:00Z"
    source: "test-engine"
`,
			filePointer: "test-sealed-secret.yaml",
			engine:      "test-engine",
			expected:    false,
		},
		{
			name: "UpdateNeededBecauseAWSARNRefHasChanged",
			kv: &api.Secret{
				Data: map[string]interface{}{
					"metadata": map[string]interface{}{
						"created_time": "2023-10-01T00:00:00Z",
						"custom_metadata": map[string]interface{}{
							"AWS_ARN_REF": "eu-north-1:123456789,eu-north-1:987654321",
						},
					},
				},
			},
			fileContent: `
metadata:
  annotations:
    AWS_ARN_REF: eu-north-1:288929571942
    created_time: "2023-10-01T00:00:00Z"
    source: "test-engine"
`,
			filePointer: "test-sealed-secret.yaml",
			engine:      "test-engine",
			expected:    true,
		},
		{
			name: "UpdateNeeded",
			kv: &api.Secret{
				Data: map[string]interface{}{
					"metadata": map[string]interface{}{
						"created_time": "2023-10-01T00:00:00Z",
					},
				},
			},
			fileContent: `
metadata:
  annotations:
    created_time: "2023-09-01T00:00:00Z"
    source: "test-engine"
`,
			filePointer: "test-sealed-secret.yaml",
			engine:      "test-engine",
			expected:    true,
		},
		{
			name: "DifferentSource",
			kv: &api.Secret{
				Data: map[string]interface{}{
					"metadata": map[string]interface{}{
						"created_time": "2023-10-01T00:00:00Z",
					},
				},
			},
			fileContent: `
metadata:
  annotations:
    created_time: "2023-10-01T00:00:00Z"
    source: "different-engine"
`,
			filePointer: "test-sealed-secret.yaml",
			engine:      "test-engine",
			expected:    false,
		},
		{
			name: "FileNotFound",
			kv: &api.Secret{
				Data: map[string]interface{}{
					"metadata": map[string]interface{}{
						"created_time": "2023-10-01T00:00:00Z",
					},
				},
			},
			filePointer: "non-existent-file.yaml",
			engine:      "test-engine",
			expected:    true,
		},
		{
			name: "InvalidYAML",
			kv: &api.Secret{
				Data: map[string]interface{}{
					"metadata": map[string]interface{}{
						"created_time": "2023-10-01T00:00:00Z",
					},
				},
			},
			fileContent: `
metadata:
  annotations:
    created_time: "2023-10-01T00:00:00Z"
    source: "test-engine
`,
			filePointer: "invalid-sealed-secret.yaml",
			engine:      "test-engine",
			expected:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.fileContent != "" {
				err := os.WriteFile(tt.filePointer, []byte(tt.fileContent), 0644)
				if err != nil {
					t.Fatalf("Failed to write test file: %v", err)
				}
				defer os.Remove(tt.filePointer)
			}

			needUpdate := readSealedSecretAndCompareWithVaultStruct("test-secret", tt.kv, tt.filePointer, tt.engine)
			if needUpdate != tt.expected {
				t.Errorf("Expected %v, but got %v", tt.expected, needUpdate)
			}
		})
	}
}
