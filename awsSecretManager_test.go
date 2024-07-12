package main

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"reflect"
	"testing"
)

func TestExtractCustomKeyFromCustomMetadata(t *testing.T) {
	// Define the custom metadata for the test
	customMetadata := map[string]interface{}{
		"custom_metadata": map[string]interface{}{
			"AWS_ARN_REF": "eu-north-1:533267334331",
		}}
	FQDNArnTestData := map[string]interface{}{
		"custom_metadata": map[string]interface{}{
			"AWS_ARN_REF": "arn:aws:secretsmanager:eu-north-1:533267334331:secret:qa01/test/demo-qHkXhm",
		}}

	// Generate the test secret with the custom metadata
	testSecret := GenerateTestSecretsWithCustomMetadata(t, customMetadata)
	FQDNSecret := GenerateTestSecretsWithCustomMetadata(t, FQDNArnTestData)

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
			name:    "FQDNArnTestData",
			key:     "AWS_ARN_REF",
			secret:  FQDNSecret,
			want:    FQDNArnTestData["custom_metadata"].(map[string]interface{})["AWS_ARN_REF"],
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
			path:    "/a01631/invalidPathShouldNeverExist",
			wantErr: true,
		},
		{
			name:    "Valid path and secret",
			path:    "/a01631/weber-test",
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

			svc, err := NewAwsSecretManager("288929571942", "nt-a01631-secretsmanager")
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
//	WriteAWSKeyValueSecret(CustomMetadataSecret, "/a01631/emil123-test")
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
					"AWS_ARN_REF": "arn:aws:secretsmanager:eu-north-1:288929571942:secret:qa01/test/demo-qHkXhm",
				}},
			secretName:  "/a01631/emil123-test",
			expectError: false,
		},
		{
			name: "valid short ARN Format",
			customMetadata: map[string]interface{}{
				"custom_metadata": map[string]interface{}{
					"AWS_ARN_REF": "eu-north-1:288929571942",
				}},
			secretName:  "/a01631/emil123-test",
			expectError: false,
		},
		{
			name:           "Missing AWS_ARN_REF Metadata",
			customMetadata: map[string]interface{}{},
			secretName:     "/a01631/emil123-test",
			expectError:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			customMetadataSecret := GenerateTestSecretsWithCustomMetadata(t, tc.customMetadata)

			// Invoke
			err := WriteAWSKeyValueSecret(customMetadataSecret, tc.secretName)

			// Assert
			if (err != nil) != tc.expectError {
				t.Errorf("WriteAWSKeyValueSecret() with %v, expected error: %v, got error: %v", tc.name, tc.expectError, err != nil)
			}
		})
	}
}

// Note: You'll need to adjust the WriteAWSKeyValueSecret function to return an error for proper error handling and testing.
// Also, ensure GenerateTestSecretsWithCustomMetadata is implemented to generate *api.Secret with the provided custom metadata.

func TestListAWSSecrets(t *testing.T) {
	svc, err := NewAwsSecretManager("", "")

	if err != nil {
		fmt.Println(err)
	}
	secretList, err := ListAWSSecrets(svc)
	if err != nil {

	}
	if secretList != nil {
		for _, v := range secretList.SecretList {
			fmt.Println(*v.Name, *v.ARN, *v.LastChangedDate)
		}
	}
}
