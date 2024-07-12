package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	awssecretmanager "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hashicorp/vault/api"
	"log"
	"log/slog"
	"strings"
)

// ARN represents the structure of an Amazon Resource Name (ARN).
type ARN struct {
	Partition string // The partition that the resource is in. For standard AWS regions, the partition is "aws". For resources in other partitions, the partition is "aws-partitionname".
	Service   string // The service namespace that identifies the AWS product (for example, Amazon S3, IAM, or Amazon RDS).
	Region    string // The region the resource resides in. Note that the ARNs for some resources do not require a region, so this component might be omitted.
	AccountID string // The ID of the AWS account that owns the resource, without hyphens. For example, 123456789012.
	Resource  string // The content of this part of the ARN varies by service. It often includes an indicator of the type of resource — for example, an IAM user or role — followed by a slash (/) or a colon (:), followed by the resource name itself.
}

func ExtractCustomKeyFromCustomMetadata(key string, secret *api.Secret) (interface{}, error) {
	customMetadata, found := GetCustomMetadataFromSecret(secret)
	if found {
		if customMetadata != nil {
			if val, ok := customMetadata[key]; ok {
				return val, nil
			}
		}
	}
	return nil, fmt.Errorf("key %s not found in custom metadata", key)
}

func ParseARN(arn string, secretEngine string, secretName string) (correctedArn *ARN, err error) {
	theRebuiltARN := ARN{}
	if strings.HasPrefix(arn, "arn:aws:secretsmanager:") {
		parts := strings.Split(arn, ":")
		if len(parts) != 7 {
			return nil, fmt.Errorf("invalid arn: %s", arn)
		}
		theRebuiltARN.Partition = "arn:aws"
		theRebuiltARN.Service = "secretsmanager"
		theRebuiltARN.Region = parts[3]
		theRebuiltARN.AccountID = parts[4]
		theRebuiltARN.Resource = fmt.Sprintf("secret:%s", parts[6])

		return &theRebuiltARN, nil
	} else {
		parts := strings.Split(arn, ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid arn: %s", arn)
		} else {
			if secretName != "" {
				secretPath := fmt.Sprintf("%s/%s", secretEngine, secretName)
				theRebuiltARN.Partition = "arn:aws"
				theRebuiltARN.Service = "secretsmanager"
				theRebuiltARN.Region = parts[0]
				theRebuiltARN.AccountID = parts[1]
				theRebuiltARN.Resource = secretPath
				return &theRebuiltARN, nil
			} else {
				return nil, fmt.Errorf("ARN is malformed: %s", arn)
			}
		}
	}
}

func GetAwsSecret(awssecretmgrsvc awssecretmanager.Client, path string) (*awssecretmanager.GetSecretValueOutput, error) {
	// Load the Shared AWS Configuration (~/.aws/config)

	input := &awssecretmanager.GetSecretValueInput{
		SecretId: aws.String(path),
	}
	result, err := awssecretmgrsvc.GetSecretValue(context.TODO(), input)
	if err != nil {
		// For a list of exceptions thrown, see
		// https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
		return nil, err
	}
	fmt.Println(result.ResultMetadata)
	return result, err
}

func CreateAWSSecret(secret api.Secret, secretName string) (secretInput *awssecretmanager.CreateSecretInput, err error) {

	dataString, err := json.Marshal(secret.Data["data"].(map[string]interface{}))

	if err != nil {
		return nil, err
	}
	secretInput = &awssecretmanager.CreateSecretInput{
		Name:         aws.String(secretName),
		SecretString: aws.String(string(dataString)),
		Tags:         nil,
	}
	return secretInput, nil
}

func WriteAWSKeyValueSecret(secret *api.Secret, secretName string) error {

	_, found := GetCustomMetadataFromSecret(secret)

	if found {
		extractedARN, err := ExtractCustomKeyFromCustomMetadata("AWS_ARN_REF", secret)
		if err != nil {
			return err
		}
		theArn, err := ParseARN(extractedARN.(string), newConfig.secretEngine, secretName)
		if err != nil {
			fmt.Println(err)
		}

		svc, err := NewAwsSecretManager(theArn.AccountID, "nt-a01631-secretsmanager")
		if err != nil {
			fmt.Println(err)

			return err
		}
		secretValueOutput, err := GetAwsSecret(*svc, secretName)
		if err != nil {
			fmt.Println(err)
			return err
		}

		if secretValueOutput == nil {
			secretInput, err := CreateAWSSecret(*secret, secretName)
			if err != nil {
				fmt.Println(err)
				return err
			}
			err = CreateSecretinAWSSecretManager(svc, secretInput)
			return err
		} else {
			secretInput, err := UpdateAWSSecret(secret, secretValueOutput.ARN)
			if err != nil {
				fmt.Println(err)
			}
			err = UpdateSecretInAWSSecretManager(svc, secretInput)
			if err != nil {
				fmt.Println(err)
			}
			return err
		}
	}
	return fmt.Errorf("desired key %s not found in secret. Could not write to AWS", "AWS_ARN_REF")
}

func UpdateAWSSecret(secret *api.Secret, arn *string) (*awssecretmanager.UpdateSecretInput, error) {
	if secret != nil {
		dataString, err := json.Marshal(secret.Data["data"].(map[string]interface{}))
		if err != nil {
			return nil, err
		}
		updateInput := awssecretmanager.UpdateSecretInput{
			SecretId:     aws.String(*arn),
			Description:  aws.String("managedby/Raven"),
			SecretString: aws.String(string(dataString)),
		}
		return &updateInput, nil
	}
	return nil, fmt.Errorf("secret is nil")
}

func CreateSecretinAWSSecretManager(svc *awssecretmanager.Client, input *awssecretmanager.CreateSecretInput) (err error) {

	createdSecret, err := svc.CreateSecret(context.TODO(), input)
	if err != nil {
		fmt.Println(err)
	}

	slog.Info("created secret in AWS Secret Manager", "secretName", *createdSecret.Name, "ARN", *createdSecret.ARN)

	return err
}
func UpdateSecretInAWSSecretManager(svc *awssecretmanager.Client, input *awssecretmanager.UpdateSecretInput) error {

	updatedSecret, err := svc.UpdateSecret(context.TODO(), input)
	if err != nil {
		return err
	}

	slog.Info("Updated secret in AWS Secret Manager", "secretName", *updatedSecret.Name, "ARN", *updatedSecret.ARN)
	return err

}

func NewAwsSecretManager(accountId string, roleName string) (*awssecretmanager.Client, error) {
	cfg, err := awsconfig.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatal(err)
	}

	// Create an STS client
	stsClient := sts.NewFromConfig(cfg)

	// Assume the role
	roleToAssume := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountId, roleName)
	//roleToAssume := "arn:aws:iam::288929571942:role/nt-a01631-secretsmanager"
	//roleToAssume := "arn:aws:iam::368583481731:role/nt-a01631-secretsmanager"

	provider := stscreds.NewAssumeRoleProvider(stsClient, roleToAssume)
	creds := aws.NewCredentialsCache(provider)

	// Create a new config with the credentials from the assumed role
	assumedRoleConfig := cfg.Copy()
	assumedRoleConfig.Credentials = creds

	svc := awssecretmanager.NewFromConfig(assumedRoleConfig)

	return svc, err
}

func ListAWSSecrets(svc *awssecretmanager.Client) (*awssecretmanager.ListSecretsOutput, error) {

	//filter := []types.Filter{
	//	{
	//		Key:    "tag-key",
	//		Values: []string{"managedby/Raven"},
	//	},
	//}

	AWSSecretList, err := svc.ListSecrets(context.TODO(), &awssecretmanager.ListSecretsInput{})
	if err != nil {
		return nil, err
	}
	return AWSSecretList, nil
}
