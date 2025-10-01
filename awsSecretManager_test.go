//go:build aws_integration
// +build aws_integration

package main

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/hashicorp/vault/api"
)

func TestExtractCustomKeyFromCustomMetadata(t *testing.T) {
	// Define the custom metadata for the test
	customMetadata := map[string]interface{}{
		"custom_metadata": map[string]interface{}{
			"AWS_ARN_REF": "eu-north-1:123456789012",
		}}
	FQDNArnTestData := map[string]interface{}{
		"custom_metadata": map[string]interface{}{
			"AWS_ARN_REF": "arn:aws:secretsmanager:eu-north-1:123456789012:secret:qa01/test/demo-qHkXhm",
		}}

	noSyncCustomMetaData := map[string]interface{}{
		"custom_metadata": map[string]interface{}{
			"AWS_ARN_REF": "arn:aws:secretsmanager:eu-north-1:123456789012:secret:qa01/test/demo-qHkXhm",
			"NO_SYNC":     "true",
		}}

	onPremEnvPrefix := map[string]interface{}{
		"custom_metadata": map[string]interface{}{
			"AWS_ARN_REF":                       "arn:aws:secretsmanager:eu-north-1:123456789012:secret:qa01/test/demo-qHkXhm",
			"ENABLE_ON_PREM_ENVIRONMENT_PREFIX": "true",
		}}

	// Generate the test secret with the custom metadata
	testSecret := GenerateTestSecretsWithCustomMetadata(t, customMetadata)
	noSyncSecret := GenerateTestSecretsWithCustomMetadata(t, noSyncCustomMetaData)
	FQDNSecret := GenerateTestSecretsWithCustomMetadata(t, FQDNArnTestData)
	onPremEnvSecretPrefixed := GenerateTestSecretsWithCustomMetadata(t, onPremEnvPrefix)

	// Define the test cases
	testCases := []struct {
		name    string
		key     string
		secret  *api.Secret
		want    interface{}
		wantErr bool
	}{
		{
			name:    "NoSecret",
			key:     "AWS_ARN_REF",
			secret:  nil,
			want:    nil,
			wantErr: true,
		},
		{
			name:    "SecretWithSpecificMetadata",
			key:     "AWS_ARN_REF",
			secret:  testSecret,
			want:    customMetadata["custom_metadata"].(map[string]interface{})["AWS_ARN_REF"],
			wantErr: false,
		},
		{
			name:    "SecretWithCustomMetaDataNoSync",
			key:     "NO_SYNC",
			secret:  noSyncSecret,
			want:    noSyncCustomMetaData["custom_metadata"].(map[string]interface{})["NO_SYNC"],
			wantErr: false,
		},
		{
			name:    "FQDNArnTestData",
			key:     "AWS_ARN_REF",
			secret:  FQDNSecret,
			want:    FQDNArnTestData["custom_metadata"].(map[string]interface{})["AWS_ARN_REF"],
			wantErr: false,
		},
		{
			name:    "onPremEnvSecretPrefixed",
			key:     "ENABLE_ON_PREM_ENVIRONMENT_PREFIX",
			secret:  onPremEnvSecretPrefixed,
			want:    onPremEnvPrefix["custom_metadata"].(map[string]interface{})["ENABLE_ON_PREM_ENVIRONMENT_PREFIX"],
			wantErr: false,
		},
	}

	// startRaven the test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fmt.Println("running test case: ", tc.name)
			got, err := ExtractCustomKeyFromCustomMetadata(tc.key, tc.secret)

			if (err != nil) != tc.wantErr {
				t.Errorf("ExtractCustomKeyFromCustomMetadata() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ExtractCustomKeyFromCustomMetadata() got = %v, want %v", got, tc.want)
			}
			t.Logf("ExtractCustomKeyFromCustomMetadata() got = %v, want %v\n", got, tc.want)
		})
	}
}

func TestGetAwsSecret(t *testing.T) {
	testCases := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "Valid starting path but not a valid(existing) secret",
			path:    "/subPath/invalidPathShouldNeverExist",
			wantErr: true,
		},
		{
			name:    "Valid path and secret",
			path:    "/subPath/weber-test",
			wantErr: false,
		},
		{
			name:    "InvalidPath",
			path:    "/invalid/path",
			wantErr: true,
		},
		{
			name:    "getNtShared",
			path:    "/nt/shared/buypass/foo-123",
			wantErr: true,
		},
		{
			name:    "EmptyPath",
			path:    "",
			wantErr: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			svc, err := NewAwsSecretManager("123456789012", "aws-specific-role-for-secretsmanager")
			//svc, err := NewAwsSecretManager("368583481731", "aws-specific-role-for-secretsmanager")
			if err != nil {
				t.Fatalf("NewAwsSecretManager() error = %v", err)
			}

			secretOutput, err := GetAwsSecret(*svc, tc.path)
			if (err != nil) != tc.wantErr {
				t.Errorf("GetAwsSecret() with path %v, error = %v, wantErr %v", tc.path, err, tc.wantErr)
			}
			if secretOutput != nil {
				fmt.Println(*secretOutput.SecretString)
			}
		})
	}
}

//func TestWriteAWSKeyValueSecret(t *testing.T) {
//
//	CustomMetadataSecret := GenerateTestSecretsWithCustomMetadata(t, nil)
//	WriteAWSKeyValueSecret(CustomMetadataSecret, "/subPath/emil123-test")
//}

func TestWriteAWSKeyValueSecret(t *testing.T) {
	testCases := []struct {
		name           string
		customMetadata map[string]interface{}
		secretName     string
		expectError    bool
	}{
		{
			name: "Valid ARN with Full Path",
			customMetadata: map[string]interface{}{
				"custom_metadata": map[string]interface{}{
					"AWS_ARN_REF": "arn:aws:secretsmanager:eu-north-1:123456789012:secret:qa01/test/demo-qHkXhm",
				}},
			secretName:  "/subPath/emil123-test",
			expectError: false,
		},
		{
			name: "valid short ARN Format",
			customMetadata: map[string]interface{}{
				"custom_metadata": map[string]interface{}{
					"AWS_ARN_REF": "eu-north-1:123456789012",
				}},
			secretName:  "/subPath/emil123-test",
			expectError: false,
		},
		{
			name:           "Missing AWS_ARN_REF Metadata",
			customMetadata: map[string]interface{}{},
			secretName:     "/subPath/emil123-test",
			expectError:    true,
		},
		{
			name: "Valid ARN(s) with Full paths",
			customMetadata: map[string]interface{}{
				"custom_metadata": map[string]interface{}{
					"AWS_ARN_REF": "arn:aws:secretsmanager:eu-north-1:123456789012:secret:qa01/test/demo-qHkXhm",
				}},
			secretName:  "/subPath/emil123-test",
			expectError: false,
		},
	}

	theConfig := config{}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			customMetadataSecret := GenerateTestSecretsWithCustomMetadata(t, tc.customMetadata)

			// Invoke
			err := WriteAWSKeyValueSecret(customMetadataSecret, tc.secretName, theConfig)

			// Assert
			if (err != nil) != tc.expectError {
				t.Errorf("WriteAWSKeyValueSecret() with %v, expected error: %v, got error: %v", tc.name, tc.expectError, err != nil)
			}
		})
	}
}

func TestListAWSSecrets(t *testing.T) {

	svc, err := NewAwsSecretManager("123456789012", "aws-specific-role-for-secretsmanager")

	if err != nil {
		fmt.Println(err)
	}
	secretList, err := ListAWSSecrets(svc)
	if err != nil {
		t.Fatal("error!", err)
	}
	if secretList != nil {
		for _, v := range secretList.SecretList {
			fmt.Println(*v.Name, *v.ARN, *v.LastChangedDate)
		}
	}
}

func TestParseARN(t *testing.T) {
	tests := []struct {
		name   string
		arn    string
		secret string
		want   []ARN
	}{
		{
			name:   "Full single ARN",
			arn:    "arn:aws:secretsmanager:eu-north-1:123456789101:secret:qa01/test/demo-qHkXhm",
			secret: "qa01/test/demo-qHkXhm",
			want: []ARN{
				{Partition: "arn:aws", Service: "secretsmanager", Region: "eu-north-1", AccountID: "123456789101", Resource: "secret:qa01/test/demo-qHkXhm"},
			},
		},
		{
			name:   "List of several full ARN",
			arn:    "arn:aws:secretsmanager:eu-north-1:123456789101:secret:qa01/test/demo-qHkXhm,arn:aws:secretsmanager:us-west-2:123456789101:secret:qa01/test/demo-qHkXhm",
			secret: "qa01/test/demo-qHkXhm",
			want: []ARN{
				{Partition: "arn:aws", Service: "secretsmanager", Region: "eu-north-1", AccountID: "123456789101", Resource: "secret:qa01/test/demo-qHkXhm"},
				{Partition: "arn:aws", Service: "secretsmanager", Region: "us-west-2", AccountID: "123456789101", Resource: "secret:qa01/test/demo-qHkXhm"},
			},
		},
		{
			name:   "Region and account number",
			arn:    "eu-north-1:123456789101",
			secret: "someSecret",
			want: []ARN{
				{Partition: "arn:aws", Service: "secretsmanager", Region: "eu-north-1", AccountID: "123456789101", Resource: "secretEngine/someSecret"},
			},
		},
		{
			name:   "mixed list of Region and account number",
			arn:    "eu-north-1:123456789101,arn:aws:secretsmanager:us-west-2:123456789101:secret:qa01/test/demo-qHkXhm",
			secret: "someSecret",
			want: []ARN{
				{Partition: "arn:aws", Service: "secretsmanager", Region: "eu-north-1", AccountID: "123456789101", Resource: "secretEngine/someSecret"},
				{Partition: "arn:aws", Service: "secretsmanager", Region: "us-west-2", AccountID: "123456789101", Resource: "secret:qa01/test/demo-qHkXhm"},
			},
		},
		{
			name:   "Invalid ARN",
			arn:    "invalid:arn",
			secret: "",
			want:   []ARN{},
		},
		{
			name:   "mixed list of Region and account number",
			arn:    "eu-north-1:123456789101,arn:aws:secretsmanager:us-west-2:123456789101:secret:qa01/test/demo-qHkXhm",
			secret: "someSecret",
			want: []ARN{
				{Partition: "arn:aws", Service: "secretsmanager", Region: "eu-north-1", AccountID: "123456789101", Resource: "secretEngine/someSecret"},
				{Partition: "arn:aws", Service: "secretsmanager", Region: "us-west-2", AccountID: "123456789101", Resource: "secret:qa01/test/demo-qHkXhm"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseARN(tt.arn, "secretEngine", tt.secret)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseARN() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeleteAWSSecrets(t *testing.T) {

	testCfg := &config{
		awsSecretPrefix: "/subPath/",
		awsRole:         "aws-specific-role-for-secretsmanager",
	}

	deleted, err := DeleteAWSSecrets("eu-north-1:123456789012", "secret-one", testCfg)

	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(*deleted.Name)
}

func TestWriteMissingAWSSecrets(t *testing.T) {
	tests := []struct {
		name              string
		currentSecretList map[string]*api.Secret
		expectedLog       string
	}{
		{
			name:              "NoSecrets",
			currentSecretList: map[string]*api.Secret{},
			expectedLog:       "",
		},
		{
			name: "SecretWithAWSARN",
			currentSecretList: map[string]*api.Secret{
				"secret1": {Data: map[string]interface{}{"metadata": map[string]interface{}{"custom_metadata": map[string]interface{}{"AWS_ARN_REF": "arn:aws:secretsmanager:region:account-id:secret:secret1"}}}},
			},
			expectedLog: "found missing secret in Vault which is not in AWS. Writing it to secret manager",
		},
		{
			name: "SecretWithoutAWSARN",
			currentSecretList: map[string]*api.Secret{
				"secret1": {Data: map[string]interface{}{"metadata": map[string]interface{}{"custom_metadata": map[string]interface{}{"OTHER_KEY": "some_value"}}}},
			},
			expectedLog: "",
		},
		{
			name: "SecretNotExistingInCurrentContext",
			currentSecretList: map[string]*api.Secret{
				"secret1": {Data: map[string]interface{}{"metadata": map[string]interface{}{"custom_metadata": map[string]interface{}{"AWS_ARN_REF": "eu-north-1:123456789012"}}, "data": map[string]interface{}{"key": "value"}}},
			},
			expectedLog: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := config{awsRole: "aws-specific-role-for-secretsmanager", awsSecretPrefix: "/subPath/"}
			WriteMissingAWSSecrets(tt.currentSecretList, c)
		})
	}
}

func TestCreateAWSSecret(t *testing.T) {
	tests := []struct {
		name          string
		secret        api.Secret
		awsSecretName string
		kmsKeyId      *string
		want          *secretsmanager.CreateSecretInput
		wantErr       bool
	}{
		{
			name: "valid secret without KMS key",
			secret: api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"username": "test",
						"password": "secret",
					},
				},
			},
			awsSecretName: "test-secret",
			kmsKeyId:      nil,
			want: &secretsmanager.CreateSecretInput{
				Name:         aws.String("test-secret"),
				SecretString: aws.String(`{"username":"test","password":"secret"}`),
				Tags:         nil,
			},
			wantErr: false,
		},
		{
			name: "valid secret with KMS key",
			secret: api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"username": "test",
						"password": "secret",
					},
				},
			},
			awsSecretName: "test-secret",
			kmsKeyId:      aws.String("test-key-id"),
			want: &secretsmanager.CreateSecretInput{
				Name:         aws.String("test-secret"),
				SecretString: aws.String(`{"username":"test","password":"secret"}`),
				KmsKeyId:     aws.String("test-key-id"),
				Tags:         nil,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateAWSSecret(tt.secret, tt.awsSecretName, tt.kmsKeyId)
			if tt.wantErr {
				t.Errorf("CreateAWSSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want.KmsKeyId != nil && got.KmsKeyId != nil {
				// Compare actual values if both pointers are non-nil
				if *tt.want.KmsKeyId != *got.KmsKeyId {
					t.Errorf("CreateAWSSecret() got = %v, want %v", got, tt.want)

				}
			}

		})
	}
}
