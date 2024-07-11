package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	sealedSecretPkg "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
	. "github.com/hashicorp/vault-plugin-secrets-kv"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"reflect"
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
	config := config{
		vaultEndpoint: cluster.Cores[0].Client.Address(),
		secretEngine:  "kv",
		token:         client.Token(),
		destEnv:       "kv",
		pemFile:       "cert.pem",
	}
	secretName := "secretsecretsecret"
	generateTestSecrets(t, client, config, secretName)
	// Pass the client to the code under test.
	_, err := getAllKVs(client, config)
	if err != nil {
		t.Fatal(err)
	}

}

func TestGetSingleKV(t *testing.T) {
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
	secrets := map[string]interface{}{
		"data":     map[string]interface{}{"secretKey": "secretValue"},
		"metadata": map[string]interface{}{"version": 2},
	}
	client.Logical().Write("kv/data/TestGetSingleKVSecret", secrets)

	list, err := getAllKVs(client, config)
	if err != nil {
		fmt.Println(err)
	}
	secretList := list.Data["keys"].([]interface{})

	persistVaultChanges(secretList, client, config)

}

func TestReadAllKV(t *testing.T) {
	//t.Parallel()
	cluster := createVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

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

	config := config{
		vaultEndpoint: cluster.Cores[0].Client.Address(),
		secretEngine:  "kv",
		token:         client.Token(),
		destEnv:       "kv",
		pemFile:       "cert.crt",
	}

	firstPath := "kv/data/TestReadAllKVsubpathone"
	secondPath := "kv/data/subpathone/TestReadAllKVsubpathtwo"
	thirdPath := "kv/data/subpathone/subpathtwo/TestReadAllKVsubpaththree"
	thirdPathv2 := "kv/data/subpathone/subpathtwo/TestReadAllKVsubpaththree"
	client.Logical().Write(firstPath, secretOne)
	client.Logical().Write(secondPath, secretTwo)
	client.Logical().Write(thirdPath, secretThree)
	client.Logical().Write(thirdPathv2, secretThreev2)

	list, err := getAllKVs(client, config)
	if err != nil {
		fmt.Println(err)
	}
	secretList := list.Data["keys"].([]interface{})
	mySecretList = map[string]*api.Secret{}
	persistVaultChanges(secretList, client, config)

	fmt.Println("TestReadAllKV len of mysecretlist:", len(mySecretList))

	for k, v := range mySecretList {
		fmt.Printf("TestReadAll -  key: %v, value: %v \n", k, v)
	}
	if len(mySecretList) != 3 {
		t.Fatal("TestReadAll list != 3. should be 3\n")
	}

}

func TestPersistVaultChanges(t *testing.T) {

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
	fmt.Println(secretList)

}

func TestGetSingleKVMultipleSubPath(t *testing.T) {
	t.Parallel()

	cluster := createVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

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

	firstPath := "kv/data/subpathone/"
	secondPath := "kv/data/subpathone/subpathtwo/"
	thirdPath := "kv/data/subpathone/subpathtwo/subpaththree/"
	thirdPathv2 := "kv/data/subpathone/subpathtwo/subpaththree/"
	client.Logical().Write(firstPath, secretOne)
	client.Logical().Write(secondPath, secretTwo)
	client.Logical().Write(thirdPath, secretThree)
	client.Logical().Write(thirdPathv2, secretThreev2)

	c := config{secretEngine: "kv"}

	secretList, err := getAllKVs(client, c)
	if err != nil {
		fmt.Println("getallKVS", err)
	}

	for _, secret := range secretList.Data["keys"].([]interface{}) {
		secret := getSingleKV(client, "kv", secret.(string))
		if secret == nil {
			fmt.Println("nil pointer exception")
		} else {
			fmt.Println("got secret", secret)
		}
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

	PreviousKV, err := getAllKVs(client, config)
	if err != nil {
		fmt.Println(err)
	}
	previousKV := PreviousKV.Data["keys"].([]interface{})

	persistVaultChanges(previousKV, client, config)
	fmt.Println("pre: setting state to this", mySecretList)
	firstState := mySecretList

	deleteTestSecrets(t, client, config, secretName)

	NewKV, err := getAllKVs(client, config)
	if err != nil {
		fmt.Println(err)
	}
	newKV := NewKV.Data["keys"].([]interface{})
	mySecretList = map[string]*api.Secret{}
	persistVaultChanges(newKV, client, config)
	fmt.Println("post: setting state to this", mySecretList)
	secondState := mySecretList

	picked := PickRipeSecrets(firstState, secondState)
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

	PreviousKV, err := getAllKVs(client, config)
	if err != nil {
		fmt.Println(err)
	}
	previousKV := PreviousKV.Data["keys"].([]interface{})

	persistVaultChanges(previousKV, client, config)
	firstState := mySecretList

	deleteTestSecrets(t, client, config, secretName)

	NewKV, err := getAllKVs(client, config)
	if err != nil {
		fmt.Println(err)
	}
	newKV := NewKV.Data["keys"].([]interface{})

	persistVaultChanges(newKV, client, config)
	secondState := mySecretList
	picked := PickRipeSecrets(firstState, secondState)
	fmt.Println(picked, len(picked))
	if len(picked) != 0 {
		t.Fatal("PickRipeSecrets should have returned 0 here")
	}
}

func createVaultTestCluster(t *testing.T) *hashivault.TestCluster {

	t.Helper()

	coreConfig := &hashivault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"kv": Factory,
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

func GenerateTestSecretsWithCustomMetadata(t *testing.T, customMetadata map[string]interface{}) *api.Secret {

	secretData := map[string]interface{}{
		"data":     map[string]interface{}{"key": "value", "many": "keys", "some": "values"},
		"metadata": customMetadata,
	}
	// Create a new Secret object
	secret := &api.Secret{
		Data: secretData,
	}

	return secret
}

func TestGetCustomMetadataFromSecret(t *testing.T) {
	tests := []struct {
		name    string
		secret  *api.Secret
		want    map[string]interface{}
		wantErr bool
	}{
		{
			name:    "secretNil",
			secret:  nil,
			want:    nil,
			wantErr: true,
		},
		{
			name:    "SecretWithEmptyMetadata",
			secret:  GenerateTestSecretsWithCustomMetadata(t, map[string]interface{}{}),
			want:    nil,
			wantErr: true,
		},
		{
			name: "SecretWithNestedMetadata",
			secret: GenerateTestSecretsWithCustomMetadata(t, map[string]interface{}{
				"custom_metadata": map[string]interface{}{
					"my_data":     "very_custom",
					"AWS_ARN_REF": "arn:partition:service:region:account-id:resource-id,arn:partition:service:region:account-id:resource-type/resource-id,arn:partition:service:region:account-id:resource-type:resource-id",
				},
			}),
			want: map[string]interface{}{
				"my_data":     "very_custom",
				"AWS_ARN_REF": "arn:partition:service:region:account-id:resource-id,arn:partition:service:region:account-id:resource-type/resource-id,arn:partition:service:region:account-id:resource-type:resource-id",
			},
			wantErr: false,
		},
		{
			name: "SecretWithNonStringMetadata",
			secret: GenerateTestSecretsWithCustomMetadata(t, map[string]interface{}{
				"custom_metadata": map[string]interface{}{
					"my_data": "very_custom",
					"test":    1234,
				},
			}),
			want: map[string]interface{}{
				"my_data": "very_custom",
				"test":    1234,
			},
			wantErr: false,
		},
		{
			name: "SecretWithNullMetadata",
			secret: GenerateTestSecretsWithCustomMetadata(t, map[string]interface{}{
				"custom_metadata": map[string]interface{}{
					"my_data": nil,
					"test":    1234,
				},
			}),
			want: map[string]interface{}{
				"my_data": nil,
				"test":    1234,
			},
			wantErr: false,
		},
		{
			name: "SecretWithNtSpecific",
			secret: GenerateTestSecretsWithCustomMetadata(t, map[string]interface{}{
				"custom_metadata": map[string]interface{}{
					"AWS_ARN_REF": "arn:aws:secretsmanager:eu-north-1:533267334331",
				},
			}),
			want: map[string]interface{}{
				"AWS_ARN_REF": "arn:aws:secretsmanager:eu-north-1:533267334331",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := GetCustomMetadataFromSecret(tt.secret)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetCustomMetadataFromSecret() = %v, want %v", got, tt.want)
			}
		})
	}
}

func GenerateCustomMetadataSecret(t *testing.T, client *api.Client, config config, secretName string, customInputData map[string]interface{}) *api.Secret {

	custom_metadata := map[string]interface{}{
		"custom_metadata": customInputData,
	}

	if customInputData != nil {
		custom_metadata = customInputData
	}

	secretData := map[string]interface{}{
		"data": map[string]interface{}{
			"secretKey": "secretValue2",
		},
		"custom_metadata": custom_metadata,
	}

	writePath := fmt.Sprintf("%s/metadata/%s", config.secretEngine, secretName)
	_, err := client.Logical().Write(writePath, secretData)
	if err != nil {
		t.Fatal(err)
	}

	writeDataPath := fmt.Sprintf("%s/data/%s", config.secretEngine, secretName)
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

func TestGetCustomMetadataFromVaultInstance(t *testing.T) {

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

	GenerateCustomMetadataSecret(t, client, config, "custom_metadataSecret", nil)

}

func TestParseARN(t *testing.T) {
	tests := []struct {
		name    string
		arn     string
		secret  string
		want    string
		wantErr bool
	}{
		{
			name:    "Full ARN",
			arn:     "arn:aws:secretsmanager:eu-north-1:533267334331:secret:qa01/test/demo-qHkXhm",
			secret:  "qa01/test/demo-qHkXhm",
			want:    "arn:aws:secretsmanager:eu-north-1:533267334331:secret:qa01/test/demo-qHkXhm",
			wantErr: false,
		},
		{
			name:    "Region and account number",
			arn:     "eu-north-1:533267334331",
			secret:  "someSecret",
			want:    "arn:aws:secretsmanager:eu-north-1:533267334331:secret:secretEngine/someSecret",
			wantErr: false,
		},
		{
			name:    "Invalid ARN",
			arn:     "invalid:arn",
			secret:  "",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			theConfig := config{secretEngine: "secretEngine"}
			got, err := ParseARN(tt.arn, theConfig, tt.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseARN() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseARN() got = %v, want %v", got, tt.want)
			}
		})
	}
}
