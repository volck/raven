package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	sealedSecretPkg "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
	kv "github.com/hashicorp/vault-plugin-secrets-kv"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/logical"
	hashivault "github.com/hashicorp/vault/vault"
)

func TestGetAllKVs(t *testing.T) {
	t.Parallel()

	cluster := createVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	// make testable secrets for cluster
	secrets := map[string]interface{}{
		"data":     map[string]interface{}{"secretKey": "secretValue"},
		"metadata": map[string]interface{}{"version": 2},
	}
	client.Logical().Write("kv/data/secret", secrets)

	// Pass the client to the code under test.
	_, err := getAllKVs(client, "secret", client.Token())
	if err != nil {
		t.Fatal(err)
	}

}

func TestGetSingleKV(t *testing.T) {
	t.Parallel()

	cluster := createVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	// make testable secrets for cluster
	secrets := map[string]interface{}{
		"data":     map[string]interface{}{"secretKey": "secretValue"},
		"metadata": map[string]interface{}{"version": 2},
	}
	client.Logical().Write("kv/data/secret", secrets)

	secret := getSingleKV(client, "kv", "secret")
	fmt.Println("TestGetSingleKV,", secret)
}

func TestValidateSelfToken(t *testing.T) {
	t.Parallel()

	cluster := createVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client
	fmt.Println("proof of TestvalidateSelftoken")
	valid := validateSelftoken(client)
	if !valid {
		t.Error("valid:", valid, client.Token())
	}

}

func TestCreatek8sSecret(t *testing.T) {
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

	singleSecret := getSingleKV(client, "kv", "secret")
	k8sSecret := createK8sSecret("secret", config, singleSecret)
	if k8sSecret.Data == nil && k8sSecret.StringData == nil {
		t.Fatal("k8sSecret nil, data not loaded")
	}
	fmt.Println("k8sSecret", k8sSecret)
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
	client.Logical().Write("kv/data/b64data", b64DataSecret)
	singleSecret := getSingleKV(client, "kv", "b64data")
	k8sSecret := createK8sSecret("b64data", config, singleSecret)
	for _, v := range k8sSecret.Data {
		if strings.Contains(string(v), "base64") {
			t.Fatal("base64 not trimmed")
		}

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

func ReturnPrivateKey(t *testing.T) map[string]*rsa.PrivateKey {
	t.Helper()
	rsaPrivateKey := `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`

	block, _ := pem.Decode([]byte(rsaPrivateKey))
	if block == nil {
		fmt.Println("failed to decode pem")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("parsePKCS1PrivateKey failed", err)
	}
	privateKeys := make(map[string]*rsa.PrivateKey)
	privateKeys["mykey"] = privateKey
	return privateKeys
}

// func generateTestSecrets(t *testing.T, client *api.Client, secretEngine string, secretName string, destEnv string, pemFile string) {

func generateTestSecrets(t *testing.T, client *api.Client, config config, secretName string) {
	t.Helper()

	// make testable secrets for cluster
	secrets := map[string]interface{}{
		"data":     map[string]interface{}{"secretKey": "secretValue"},
		"metadata": map[string]interface{}{"version": 2},
	}
	writePath := fmt.Sprintf("%s/data/%s", config.secretEngine, secretName)
	client.Logical().Write(writePath, secrets)

}

func deleteTestSecrets(t *testing.T, client *api.Client, config config, secretName string) {
	t.Helper()
	dataPath := fmt.Sprintf("%s/data/%s", config.secretEngine, secretName)
	client.Logical().Delete(dataPath)
	metadataPath := fmt.Sprintf("%s/metadata/%s", config.secretEngine, secretName)
	client.Logical().Delete(metadataPath)

}

//func ReadConvertKVFromVault(t *testing.T, client *api.Client, secretEngine string, secretName string, destEnv string, pemFile string) (*sealedSecretPkg.SealedSecret, v1.Secret) {
func ReadConvertKVFromVault(t *testing.T, client *api.Client, secretEngine string, secretName string, destEnv string, pemFile string) (*sealedSecretPkg.SealedSecret, v1.Secret) {
	t.Helper()
	// make testable secrets for cluster
	cluster := createVaultTestCluster(t)
	defer cluster.Cleanup()
	client = cluster.Cores[0].Client

	config := config{
		vaultEndpoint: cluster.Cores[0].Client.Address(),
		secretEngine:  "kv",
		token:         client.Token(),
		destEnv:       "kv",
	}
	generateTestSecrets(t, client, config, secretName)
	SingleKVFromVault := getSingleKV(client, secretEngine, secretName)
	k8sSecret := createK8sSecret(secretName, config, SingleKVFromVault)
	SealedSecret := createSealedSecret(pemFile, &k8sSecret)
	return SealedSecret, k8sSecret
}

func UnsealSecretAndReturn(t *testing.T, SealedSecret *sealedSecretPkg.SealedSecret, codecs serializer.CodecFactory, privateKeys map[string]*rsa.PrivateKey) *v1.Secret {
	t.Helper()

	UnsealedSecret, err := SealedSecret.Unseal(codecs, privateKeys)
	if err != nil {
		fmt.Println("unsealedSecret:", err)
	}
	return UnsealedSecret
}

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

func createVaultTestCluster(t *testing.T) *hashivault.TestCluster {

	t.Helper()

	coreConfig := &hashivault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"kv": kv.Factory,
		},
	}
	cluster := hashivault.NewTestCluster(t, coreConfig, &hashivault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()

	// Create KV V2 mount
	if err := cluster.Cores[0].Client.Sys().Mount("kv", &api.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2",
		},
	}); err != nil {
		t.Fatal(err)
	}

	return cluster
}

func TestPickRipeSecretsReturnsOne(t *testing.T) {
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
	secretNameTwo := "secrettwo"
	generateTestSecrets(t, client, config, secretName)
	generateTestSecrets(t, client, config, secretNameTwo)

	PreviousKV, err := getAllKVs(client, config.secretEngine, client.Token())
	if err != nil {
		fmt.Println(err)
	}

	deleteTestSecrets(t, client, config, secretName)

	newKV, err := getAllKVs(client, config.secretEngine, client.Token())
	if err != nil {
		fmt.Println(err)
	}

	picked := PickRipeSecrets(PreviousKV, newKV)
	fmt.Println(picked, len(picked))
	if len(picked) == 0 {
		t.Fatal("PickRipeSecrets should have returned 1 here")
	}
}

func TestPickRipeSecretsReturnsNoRipe(t *testing.T) {
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
	secretNameTwo := "secrettwo"
	generateTestSecrets(t, client, config, secretName)
	generateTestSecrets(t, client, config, secretNameTwo)

	PreviousKV, err := getAllKVs(client, config.secretEngine, client.Token())
	if err != nil {
		fmt.Println(err)
	}

	newKV, err := getAllKVs(client, config.secretEngine, client.Token())
	if err != nil {
		fmt.Println(err)
	}

	picked := PickRipeSecrets(PreviousKV, newKV)
	fmt.Println(picked, len(picked))
	if len(picked) != 0 {
		t.Fatal("PickRipeSecrets should have returned 1 here")
	}
}