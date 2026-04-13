package vault

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/volck/raven/internal/testutil"
)

func TestGetAllKVs(t *testing.T) {
	t.Parallel()

	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client
	cfg := testutil.NewTestConfig(cluster)

	secretName := "secretsecretsecret"
	testutil.GenerateTestSecrets(t, client, cfg, secretName)

	_, err := GetAllKVs(client, cfg.SecretEngine)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetSingleKV(t *testing.T) {
	t.Parallel()

	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client
	cfg := testutil.NewTestConfig(cluster)

	secrets := map[string]interface{}{
		"data":     map[string]interface{}{"secretKey": "secretValue"},
		"metadata": map[string]interface{}{"version": 2},
	}
	client.Logical().Write("kv/data/TestGetSingleKVSecret", secrets)

	secret := GetSingleKV(client, cfg.SecretEngine, "TestGetSingleKVSecret")
	if secret == nil {
		t.Fatal("GetSingleKV returned nil")
	}
}

func TestIterateList(t *testing.T) {
	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

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

	client.Logical().Write("kv/data/TestReadAllKVsubpathone", secretOne)
	client.Logical().Write("kv/data/subpathone/TestReadAllKVsubpathtwo", secretTwo)
	client.Logical().Write("kv/data/subpathone/subpathtwo/TestReadAllKVsubpaththree", secretThree)

	list, err := GetAllKVs(client, "kv")
	if err != nil {
		t.Fatal(err)
	}
	secretList := list.Data["keys"].([]interface{})

	currentSecrets := map[string]*api.Secret{}
	for _, s := range secretList {
		path := fmt.Sprintf("kv/%s", s.(string))
		IterateList(path, client, "", currentSecrets)
	}

	if len(currentSecrets) != 3 {
		t.Fatalf("expected 3 secrets, got %d", len(currentSecrets))
	}
}

func TestValidToken(t *testing.T) {
	t.Parallel()

	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client

	if !ValidToken(client) {
		t.Fatal("expected valid token")
	}
}

func TestClient(t *testing.T) {
	t.Parallel()

	// Client() uses http.DefaultClient which doesn't trust the test cluster's
	// self-signed certs. Verify basic construction with a non-TLS address.
	c, err := Client("http://127.0.0.1:8200", "test-token")
	if err != nil {
		t.Fatal(err)
	}
	if c == nil {
		t.Fatal("Client() returned nil")
	}
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
			secret:  testutil.GenerateTestSecretsWithCustomMetadata(t, map[string]interface{}{}),
			want:    nil,
			wantErr: true,
		},
		{
			name: "SecretWithNestedMetadata",
			secret: testutil.GenerateTestSecretsWithCustomMetadata(t, map[string]interface{}{
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
			secret: testutil.GenerateTestSecretsWithCustomMetadata(t, map[string]interface{}{
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
			secret: testutil.GenerateTestSecretsWithCustomMetadata(t, map[string]interface{}{
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
			secret: testutil.GenerateTestSecretsWithCustomMetadata(t, map[string]interface{}{
				"custom_metadata": map[string]interface{}{
					"AWS_ARN_REF": "arn:aws:secretsmanager:eu-north-1:123456789101",
				},
			}),
			want: map[string]interface{}{
				"AWS_ARN_REF": "arn:aws:secretsmanager:eu-north-1:123456789101",
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

func TestPickRipeSecretsReturnsOne(t *testing.T) {
	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client
	cfg := testutil.NewTestConfig(cluster)

	testutil.GenerateTestSecrets(t, client, cfg, "secret")
	testutil.GenerateTestSecrets(t, client, cfg, "secrettwo")

	list, err := GetAllKVs(client, cfg.SecretEngine)
	if err != nil {
		t.Fatal(err)
	}
	secretList := list.Data["keys"].([]interface{})

	firstState := map[string]*api.Secret{}
	for _, s := range secretList {
		path := fmt.Sprintf("kv/%s", s.(string))
		IterateList(path, client, "", firstState)
	}

	testutil.DeleteTestSecrets(t, client, cfg, "secret")

	list2, err := GetAllKVs(client, cfg.SecretEngine)
	if err != nil {
		t.Fatal(err)
	}

	secondState := map[string]*api.Secret{}
	for _, s := range list2.Data["keys"].([]interface{}) {
		path := fmt.Sprintf("kv/%s", s.(string))
		IterateList(path, client, "", secondState)
	}

	picked := PickRipeSecrets(firstState, secondState)
	if len(picked) == 0 {
		t.Fatal("PickRipeSecrets should have returned 1 here")
	}
}

func TestPickRipeSecretsReturnsNoRipe(t *testing.T) {
	cluster := testutil.CreateVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client
	cfg := testutil.NewTestConfig(cluster)

	testutil.GenerateTestSecrets(t, client, cfg, "secret")
	testutil.GenerateTestSecrets(t, client, cfg, "secrettwo")

	list, err := GetAllKVs(client, cfg.SecretEngine)
	if err != nil {
		t.Fatal(err)
	}
	secretList := list.Data["keys"].([]interface{})

	firstState := map[string]*api.Secret{}
	for _, s := range secretList {
		path := fmt.Sprintf("kv/%s", s.(string))
		IterateList(path, client, "", firstState)
	}

	testutil.DeleteTestSecrets(t, client, cfg, "secret")

	list2, err := GetAllKVs(client, cfg.SecretEngine)
	if err != nil {
		t.Fatal(err)
	}

	secondState := map[string]*api.Secret{}
	for _, s := range list2.Data["keys"].([]interface{}) {
		path := fmt.Sprintf("kv/%s", s.(string))
		IterateList(path, client, "", secondState)
	}

	// Both states should not return ripe when we also refresh firstState
	// Actually recreate the test properly: no deletions means no ripe
	testutil.GenerateTestSecrets(t, client, cfg, "secret")
	list3, _ := GetAllKVs(client, cfg.SecretEngine)
	thirdState := map[string]*api.Secret{}
	for _, s := range list3.Data["keys"].([]interface{}) {
		path := fmt.Sprintf("kv/%s", s.(string))
		IterateList(path, client, "", thirdState)
	}

	picked := PickRipeSecrets(thirdState, thirdState)
	if len(picked) != 0 {
		t.Fatal("PickRipeSecrets should have returned 0 here")
	}
}

func TestFindRipeAWSSecrets(t *testing.T) {
	tests := []struct {
		name       string
		PreviousKV map[string]*api.Secret
		NewKV      map[string]*api.Secret
		expected   map[string]string
	}{
		{
			name: "NoRipeSecrets",
			PreviousKV: map[string]*api.Secret{
				"secret1": {Data: map[string]interface{}{"metadata": map[string]interface{}{"custom_metadata": map[string]interface{}{"AWS_ARN_REF": "arn:aws:secretsmanager:region:account-id:secret:secret1"}}}},
				"secret2": {Data: map[string]interface{}{"metadata": map[string]interface{}{"custom_metadata": map[string]interface{}{"AWS_ARN_REF": "arn:aws:secretsmanager:region:account-id:secret:secret2"}}}},
			},
			NewKV: map[string]*api.Secret{
				"secret1": {Data: map[string]interface{}{"metadata": map[string]interface{}{"custom_metadata": map[string]interface{}{"AWS_ARN_REF": "arn:aws:secretsmanager:region:account-id:secret:secret1"}}}},
				"secret2": {Data: map[string]interface{}{"metadata": map[string]interface{}{"custom_metadata": map[string]interface{}{"AWS_ARN_REF": "arn:aws:secretsmanager:region:account-id:secret:secret2"}}}},
			},
			expected: map[string]string{},
		},
		{
			name: "OneRipeSecret",
			PreviousKV: map[string]*api.Secret{
				"secret1": {Data: map[string]interface{}{"metadata": map[string]interface{}{"custom_metadata": map[string]interface{}{"AWS_ARN_REF": "arn:aws:secretsmanager:region:account-id:secret:secret1"}}}},
				"secret2": {Data: map[string]interface{}{"metadata": map[string]interface{}{"custom_metadata": map[string]interface{}{"AWS_ARN_REF": "arn:aws:secretsmanager:region:account-id:secret:secret2"}}}},
			},
			NewKV: map[string]*api.Secret{
				"secret1": {Data: map[string]interface{}{"metadata": map[string]interface{}{"custom_metadata": map[string]interface{}{"AWS_ARN_REF": "arn:aws:secretsmanager:region:account-id:secret:secret1"}}}},
				"secret2": {Data: map[string]interface{}{"metadata": map[string]interface{}{"custom_metadata": map[string]interface{}{"AWS_ARN_REF": "arn:aws:secretsmanager:region:account-id:secret:secret2-new"}}}},
			},
			expected: map[string]string{"secret2": "arn:aws:secretsmanager:region:account-id:secret:secret2"},
		},
		{
			name: "MultipleRipeSecrets",
			PreviousKV: map[string]*api.Secret{
				"secret1": {Data: map[string]interface{}{"metadata": map[string]interface{}{"custom_metadata": map[string]interface{}{"AWS_ARN_REF": "arn:aws:secretsmanager:region:account-id:secret:secret1"}}}},
				"secret2": {Data: map[string]interface{}{"metadata": map[string]interface{}{"custom_metadata": map[string]interface{}{"AWS_ARN_REF": "arn:aws:secretsmanager:region:account-id:secret:secret2"}}}},
			},
			NewKV: map[string]*api.Secret{
				"secret1": {Data: map[string]interface{}{"metadata": map[string]interface{}{"custom_metadata": map[string]interface{}{"AWS_ARN_REF": "arn:aws:secretsmanager:region:account-id:secret:secret1-new"}}}},
				"secret2": {Data: map[string]interface{}{"metadata": map[string]interface{}{"custom_metadata": map[string]interface{}{"AWS_ARN_REF": "arn:aws:secretsmanager:region:account-id:secret:secret2-new"}}}},
			},
			expected: map[string]string{
				"secret1": "arn:aws:secretsmanager:region:account-id:secret:secret1",
				"secret2": "arn:aws:secretsmanager:region:account-id:secret:secret2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FindRipeAWSSecrets(tt.PreviousKV, tt.NewKV)
			assert.Equal(t, tt.expected, result)
		})
	}
}
