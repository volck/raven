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
	"os"
	"strings"
	"time"
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

func ParseARN(arn string, secretEngine string, secretName string) (correctedArn []ARN) {
	arnSplit := strings.Split(arn, ",")
	parsedArns := []ARN{}
	for _, singleArn := range arnSplit {
		theRebuiltARN := ARN{}
		if strings.HasPrefix(singleArn, "arn:aws:secretsmanager:") {
			parts := strings.Split(singleArn, ":")
			if len(parts) != 7 {
				return nil
			}
			theRebuiltARN.Partition = "arn:aws"
			theRebuiltARN.Service = "secretsmanager"
			theRebuiltARN.Region = parts[3]
			theRebuiltARN.AccountID = parts[4]
			theRebuiltARN.Resource = fmt.Sprintf("secret:%s", parts[6])
			parsedArns = append(parsedArns, theRebuiltARN)
		} else {
			parts := strings.Split(singleArn, ":")
			if len(parts) != 2 {
				jsonLogger.Info("ARN is malformed", "arn", arn)
			} else {
				if secretName != "" {
					theRebuiltARN = ARN{}
					secretPath := fmt.Sprintf("%s/%s", secretEngine, secretName)
					theRebuiltARN.Partition = "arn:aws"
					theRebuiltARN.Service = "secretsmanager"
					theRebuiltARN.Region = parts[0]
					theRebuiltARN.AccountID = parts[1]
					theRebuiltARN.Resource = secretPath
					parsedArns = append(parsedArns, theRebuiltARN)
				} else {
					jsonLogger.Info("ARN is malformed", "arn", arn)
				}
			}
		}
	}
	return parsedArns
}
func GetAwsSecret(awssecretmgrsvc awssecretmanager.Client, path string) (*awssecretmanager.GetSecretValueOutput, error) {

	AwsSecretPrefix := os.Getenv("AWS_SECRET_PREFIX")

	if AwsSecretPrefix != "" {

		input := &awssecretmanager.GetSecretValueInput{
			SecretId: aws.String(path),
		}
		result, err := awssecretmgrsvc.GetSecretValue(context.TODO(), input)
		if err != nil {

			// For a list of exceptions thrown, see
			// https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
			return nil, err
		}
		return result, err
	}
	return nil, fmt.Errorf("AWS_SECRET_PREFIX not set")
}

func CreateAWSSecret(secret api.Secret, awsSecretName string, KmsKeyId *string) (secretInput *awssecretmanager.CreateSecretInput, err error) {

	dataString, err := json.Marshal(secret.Data["data"].(map[string]interface{}))

	if err != nil {
		return nil, err
	}
	secretInput = &awssecretmanager.CreateSecretInput{
		Name:         aws.String(awsSecretName),
		SecretString: aws.String(string(dataString)),
		Tags:         nil,
	}
	if KmsKeyId != nil {
		jsonLogger.Info("found KMS key", "KmsKeyId", *KmsKeyId, "awsSecretName", awsSecretName)
		secretInput.KmsKeyId = KmsKeyId
	}
	return secretInput, nil
}

func WriteAWSKeyValueSecret(secret *api.Secret, secretName string, theConfig config) error {

	_, found := GetCustomMetadataFromSecret(secret)

	awsSecretPrefix := os.Getenv("AWS_SECRET_PREFIX")
	awsRole := os.Getenv("AWS_ROLE_NAME")
	if found && awsSecretPrefix != "" {
		enableEnvironmentPrefix, err := ExtractCustomKeyFromCustomMetadata("ENABLE_ON_PREM_ENVIRONMENT_PREFIX", secret)
		if err != nil {
			jsonLogger.Error("error extracting key from custom metadata", "error", err, "key", "ENABLE_ON_PREM_ENVIRONMENT_PREFIX")
		}
		jsonLogger.Info("ENABLE_ON_PREM_ENVIRONMENT_PREFIX", "enableEnvironmentPrefix", enableEnvironmentPrefix)
		if enableEnvironmentPrefix == "true" {
			jsonLogger.Info("ENABLE_ON_PREM_ENVIRONMENT_PREFIX is set. Using secretengine prefix", "secretEngine", theConfig.secretEngine)
			secretName = fmt.Sprintf("%s/%s/%s", awsSecretPrefix, theConfig.secretEngine, secretName)
		} else {
			secretName = fmt.Sprintf("%s/%s", awsSecretPrefix, secretName)
		}
		extractedARN, err := ExtractCustomKeyFromCustomMetadata("AWS_ARN_REF", secret)
		if err != nil {
			return err
		}
		if extractedARN != nil {
			newextractedKmsKeyId := new(string)
			extractedKmsKeyId, _ := ExtractCustomKeyFromCustomMetadata("AWS_KMS_KEY", secret)
			parsedARNs := ParseARN(extractedARN.(string), newConfig.secretEngine, secretName)

			if extractedKmsKeyId != nil {
				jsonLogger.Info("secret has KMS key defined.. Setting KMS key", "KmsKeyId", extractedKmsKeyId.(string))
				*newextractedKmsKeyId = extractedKmsKeyId.(string)
			}

			if parsedARNs != nil {
				for _, parsedArn := range parsedARNs {
					svc, err := NewAwsSecretManager(parsedArn.AccountID, awsRole)
					if err != nil {
						jsonLogger.Error("error creating AWS Secret Manager client", "error", err)
						return err
					}

					secretValueOutput, err := GetAwsSecret(*svc, secretName)
					if err != nil {
						jsonLogger.Error("GetAwsSecret error", "error", err)
					}

					if secretValueOutput == nil {
						secretInput, err := CreateAWSSecret(*secret, secretName, newextractedKmsKeyId)
						if err != nil {
							jsonLogger.Error("error creating secret object for AWS Secret Manager", "error", err)
						}
						err = CreateAWSSecretInManager(svc, secretInput)
						if err != nil {
							jsonLogger.Error("could not create aws secret in manager", "error", err)
						}
					} else {
						secretInput, err := UpdateAWSSecret(secret, *secretValueOutput.ARN, newextractedKmsKeyId)
						if err != nil {
							jsonLogger.Error("error updating secret in AWS Secret Manager", "error", err)
						}
						err = UpdateSecretInAWSSecretManager(svc, secretInput)
						if err != nil {
							jsonLogger.Error("error updating secret in AWS Secret Manager", "error", err)
						}
					}
				}
			}
		}
		if extractedARN == nil {
			return fmt.Errorf("desired key %s not found in secret. Could not write to AWS", "AWS_ARN_REF")
		}
	}
	return nil
}

func UpdateAWSSecret(secret *api.Secret, secretIdArn string, KmsKeyId *string) (*awssecretmanager.UpdateSecretInput, error) {
	if secret != nil {
		dataString, err := json.Marshal(secret.Data["data"].(map[string]interface{}))
		if err != nil {
			return nil, err
		}
		updateInput := awssecretmanager.UpdateSecretInput{
			SecretId:     aws.String(secretIdArn),
			Description:  aws.String("managedby/Raven"),
			SecretString: aws.String(string(dataString)),
		}
		if KmsKeyId != nil {
			jsonLogger.Info("secret has KMS key defined.. Setting KMS key", "KmsKeyId", *KmsKeyId)
			updateInput.KmsKeyId = KmsKeyId
		}
		return &updateInput, nil
	}
	return nil, fmt.Errorf("secret is nil")
}

func CreateAWSSecretInManager(svc *awssecretmanager.Client, input *awssecretmanager.CreateSecretInput) (err error) {

	createdSecret, err := svc.CreateSecret(context.TODO(), input)
	if err != nil {
		jsonLogger.Error("error creating secret in AWS Secret Manager", "error", err)
	} else {

		jsonLogger.Info("created secret in AWS Secret Manager", "secretName", *createdSecret.Name, "ARN", *createdSecret.ARN)
		AWSWebHookUrl := os.Getenv("AWS_NOTIFICATION_WEBHOOK_URL")
		if AWSWebHookUrl != "" {
			msgText := fmt.Sprintf("Raven created secret %v in AWS Secret Manager with the ARN %s", *createdSecret.Name, *createdSecret.ARN)
			NotifyTeamsChannel("Raven created secret in AWS Secret Manager", msgText, AWSWebHookUrl)
		}
	}
	return err
}
func UpdateSecretInAWSSecretManager(svc *awssecretmanager.Client, input *awssecretmanager.UpdateSecretInput) error {

	AwsSecretPrefix := os.Getenv("AWS_SECRET_PREFIX")

	if AwsSecretPrefix != "" {

		updatedSecret, err := svc.UpdateSecret(context.TODO(), input)
		if err != nil {
			return err
		}

		jsonLogger.Info("Updated secret in AWS Secret Manager", "secretName", *updatedSecret.Name, "ARN", *updatedSecret.ARN)
		AWSWebHookUrl := os.Getenv("AWS_NOTIFICATION_WEBHOOK_URL")
		if AWSWebHookUrl != "" {
			msgText := fmt.Sprintf("Raven updated secret(%v) with the ARN %v", *updatedSecret.Name, updatedSecret.ARN)
			NotifyTeamsChannel("Raven updated secret in AWS Secret Manager", msgText, AWSWebHookUrl)
		}
		return err
	}
	return fmt.Errorf("AWS_SECRET_PREFIX not set")

}

func NewAwsSecretManager(accountId string, awsRoleName string) (*awssecretmanager.Client, error) {
	cfg, err := awsconfig.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatal(err)
	}

	// Create an STS client
	stsClient := sts.NewFromConfig(cfg)

	// Assume the role
	roleToAssume := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountId, awsRoleName)
	jsonLogger.Info("attempting to use role", "role", roleToAssume)
	provider := stscreds.NewAssumeRoleProvider(stsClient, roleToAssume)
	creds := aws.NewCredentialsCache(provider)
	// Create a new config with the credentials from the assumed role
	assumedRoleConfig := cfg.Copy()
	assumedRoleConfig.Credentials = creds

	svc := awssecretmanager.NewFromConfig(assumedRoleConfig)
	return svc, err
}

func ListAWSSecrets(svc *awssecretmanager.Client) (*awssecretmanager.ListSecretsOutput, error) {

	AWSSecretList, err := svc.ListSecrets(context.TODO(), &awssecretmanager.ListSecretsInput{})
	if err != nil {
		return nil, err
	}
	return AWSSecretList, nil
}

func DeleteAWSSecrets(Arn string, secretName string, cfg *config) (*awssecretmanager.DeleteSecretOutput, error) {

	secretName = fmt.Sprintf("%s/%s", cfg.awsSecretPrefix, secretName)

	if cfg.awsSecretPrefix != "" {
		parsedArn := ParseARN(Arn, cfg.secretEngine, secretName)
		fmt.Println(parsedArn[0])
		if parsedArn != nil {
			svc, err := NewAwsSecretManager(parsedArn[0].AccountID, cfg.awsRole)
			if err != nil {
				jsonLogger.Error("error creating AWS Secret Manager client", "error", err)
			}
			deletedSecret, err := svc.DeleteSecret(context.TODO(), &awssecretmanager.DeleteSecretInput{SecretId: aws.String(secretName)})
			if err != nil {
				jsonLogger.Info("error deleting secret in AWS Secret Manager", "error", err)
				return nil, err
			}
			jsonLogger.Info("deleted secret in AWS Secret Manager", "ArnRef", *deletedSecret.Name, "ARN", *deletedSecret.ARN)
			return deletedSecret, nil
		}
	}
	return nil, fmt.Errorf("error parsing ARN")
}

func HarvestRipeAwsSecrets(ripeSecrets map[string]string, c config) {
	for secretName, ripe := range ripeSecrets {
		jsonLogger.Info("HarvestRipeSecrets found ripe secret. Deleting in AWS secrets manager", "ripeSecret", ripe)
		deletedSecret, err := DeleteAWSSecrets(ripe, secretName, &c)
		if err != nil {
			jsonLogger.Info("error deleting secret in AWS Secret Manager", "error", err, "ripeSecret", ripe)
		}
		jsonLogger.Info("HarvestRipeSecrets found ripe secret. Deleting in AWS secrets manager", "ripeSecret", *deletedSecret.Name, "date", *deletedSecret.DeletionDate)
	}
}

func WriteMissingAWSSecrets(currentSecretList map[string]*api.Secret, c config) {
	t := time.Now()

	minute := t.Minute()

	if minute > 25 && minute <= 30 || minute > 55 && minute <= 60 {

		jsonLogger.Info("checking for missing aws secrets")
		jsonLogger.Info("AWS envvars", "AWS_SECRET_PREFIX", os.Getenv("AWS_SECRET_PREFIX"), "AWS_ROLE_NAME", os.Getenv("AWS_ROLE_NAME"))
		for secretName, val := range currentSecretList {
			_, found := GetCustomMetadataFromSecret(val)
			awsSecretPrefix := os.Getenv("AWS_SECRET_PREFIX")
			if found && awsSecretPrefix != "" {

				extractedKeys, err := ExtractCustomKeyFromCustomMetadata("AWS_ARN_REF", val)
				if err != nil {
					jsonLogger.Debug("error extracting key from custom metadata", "error", err)
					continue
				}
				if extractedKeys == nil {
					jsonLogger.Debug("extracted key is nil")
					continue
				}
				correctedArns := ParseARN(extractedKeys.(string), newConfig.secretEngine, secretName)
				jsonLogger.Info("found these arns", "correctedArns", correctedArns)
				if len(correctedArns) > 0 {
					for _, correctedArn := range correctedArns {
						svc, err := NewAwsSecretManager(correctedArn.AccountID, c.awsRole)
						if err != nil {
							jsonLogger.Error("error creating AWS Secret Manager client", "error", err)
						}
						newextractedKmsKeyId := new(string)
						extractedKmsKeyId, _ := ExtractCustomKeyFromCustomMetadata("AWS_KMS_KEY", val)

						if extractedKmsKeyId != nil {
							*newextractedKmsKeyId = extractedKmsKeyId.(string)
							fmt.Println(*newextractedKmsKeyId)
						}

						awsPrefixSecretName := fmt.Sprintf("%s/%s", awsSecretPrefix, secretName)
						secretOutput, err := GetAwsSecret(*svc, awsPrefixSecretName)
						if err != nil {
							jsonLogger.Info("error getting secret from AWS Secret Manager", "error", err)
						}
						if secretOutput == nil {
							jsonLogger.Info("found missing secret in Vault which is not in AWS. Writing it to secret manager", "awsPrefixSecretName", awsPrefixSecretName)
							secretInput, err := CreateAWSSecret(*val, awsPrefixSecretName, newextractedKmsKeyId)
							if err != nil {
								jsonLogger.Info("error creating secret in AWS Secret Manager", "error", err)
							}
							err = CreateAWSSecretInManager(svc, secretInput)
							if err != nil {
								jsonLogger.Info("error creating secret in AWS Secret Manager", "error", err)
							}
						} else {
							jsonLogger.Info("found secret in AWS Secret Manager", "awsPrefixSecretName", awsPrefixSecretName)
						}
					}
				}
			}
		}
	}
}
