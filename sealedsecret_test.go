package main

import (
	"fmt"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
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