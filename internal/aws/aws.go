package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	awssecretmanager "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hashicorp/vault/api"

	"github.com/volck/raven/internal/config"
	"github.com/volck/raven/internal/helpers"
	vaultpkg "github.com/volck/raven/internal/vault"
)

var jsonLogger = helpers.JsonLogger

type ARN struct {
	Partition string
	Service   string
	Region    string
	AccountID string
	Resource  string
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
			SecretId: awssdk.String(path),
		}
		result, err := awssecretmgrsvc.GetSecretValue(context.TODO(), input)
		if err != nil {
			return nil, err
		}
		return result, err
	}
	return nil, fmt.Errorf("AWS_SECRET_PREFIX not set")
}

func CreateAWSSecret(secret api.Secret, awsSecretName string, KmsKeyId *string) (*awssecretmanager.CreateSecretInput, error) {
	dataString, err := json.Marshal(secret.Data["data"].(map[string]interface{}))
	if err != nil {
		return nil, err
	}
	secretInput := &awssecretmanager.CreateSecretInput{
		Name:         awssdk.String(awsSecretName),
		SecretString: awssdk.String(string(dataString)),
		Tags:         nil,
	}
	if KmsKeyId != nil {
		jsonLogger.Info("found KMS key", "KmsKeyId", *KmsKeyId, "awsSecretName", awsSecretName)
		secretInput.KmsKeyId = KmsKeyId
	}
	return secretInput, nil
}

func WriteAWSKeyValueSecret(secret *api.Secret, secretName string, cfg config.Config) error {
	_, found := vaultpkg.GetCustomMetadataFromSecret(secret)

	awsSecretPrefix := os.Getenv("AWS_SECRET_PREFIX")
	awsRole := os.Getenv("AWS_ROLE_NAME")
	if found && awsSecretPrefix != "" {
		enableEnvironmentPrefix, err := vaultpkg.ExtractCustomKeyFromCustomMetadata("ENABLE_ON_PREM_ENVIRONMENT_PREFIX", secret)
		if err != nil {
			jsonLogger.Error("error extracting key from custom metadata", "error", err)
		}
		if enableEnvironmentPrefix == "true" {
			secretName = fmt.Sprintf("%s/%s/%s", awsSecretPrefix, cfg.SecretEngine, secretName)
		} else {
			secretName = fmt.Sprintf("%s/%s", awsSecretPrefix, secretName)
		}
		extractedARN, err := vaultpkg.ExtractCustomKeyFromCustomMetadata("AWS_ARN_REF", secret)
		if err != nil {
			return err
		}
		if extractedARN != nil {
			newextractedKmsKeyId := new(string)
			extractedKmsKeyId, _ := vaultpkg.ExtractCustomKeyFromCustomMetadata("AWS_KMS_KEY", secret)
			parsedARNs := ParseARN(extractedARN.(string), cfg.SecretEngine, secretName)

			if extractedKmsKeyId != nil {
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
			SecretId:     awssdk.String(secretIdArn),
			Description:  awssdk.String("managedby/Raven"),
			SecretString: awssdk.String(string(dataString)),
		}
		if KmsKeyId != nil {
			updateInput.KmsKeyId = KmsKeyId
		}
		return &updateInput, nil
	}
	return nil, fmt.Errorf("secret is nil")
}

func CreateAWSSecretInManager(svc *awssecretmanager.Client, input *awssecretmanager.CreateSecretInput) error {
	createdSecret, err := svc.CreateSecret(context.TODO(), input)
	if err != nil {
		jsonLogger.Error("error creating secret in AWS Secret Manager", "error", err)
	} else {
		jsonLogger.Info("created secret in AWS Secret Manager", "secretName", *createdSecret.Name, "ARN", *createdSecret.ARN)
		AWSWebHookUrl := os.Getenv("AWS_NOTIFICATION_WEBHOOK_URL")
		if AWSWebHookUrl != "" {
			msgText := fmt.Sprintf("Raven created secret %v in AWS Secret Manager with the ARN %s", *createdSecret.Name, *createdSecret.ARN)
			helpers.NotifyTeamsChannel("Raven created secret in AWS Secret Manager", msgText, AWSWebHookUrl)
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
			helpers.NotifyTeamsChannel("Raven updated secret in AWS Secret Manager", msgText, AWSWebHookUrl)
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
	stsClient := sts.NewFromConfig(cfg)
	roleToAssume := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountId, awsRoleName)
	jsonLogger.Info("attempting to use role", "role", roleToAssume)
	provider := stscreds.NewAssumeRoleProvider(stsClient, roleToAssume)
	creds := awssdk.NewCredentialsCache(provider)
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

func DeleteAWSSecrets(Arn string, secretName string, cfg *config.Config) (*awssecretmanager.DeleteSecretOutput, error) {
	secretName = fmt.Sprintf("%s/%s", cfg.AwsSecretPrefix, secretName)
	if cfg.AwsSecretPrefix != "" {
		parsedArn := ParseARN(Arn, cfg.SecretEngine, secretName)
		if parsedArn != nil {
			svc, err := NewAwsSecretManager(parsedArn[0].AccountID, cfg.AwsRole)
			if err != nil {
				jsonLogger.Error("error creating AWS Secret Manager client", "error", err)
			}
			deletedSecret, err := svc.DeleteSecret(context.TODO(), &awssecretmanager.DeleteSecretInput{SecretId: awssdk.String(secretName)})
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

func HarvestRipeAwsSecrets(ripeSecrets map[string]string, cfg config.Config) {
	for secretName, ripe := range ripeSecrets {
		jsonLogger.Info("HarvestRipeSecrets found ripe secret. Deleting in AWS secrets manager", "ripeSecret", ripe)
		deletedSecret, err := DeleteAWSSecrets(ripe, secretName, &cfg)
		if err != nil {
			jsonLogger.Info("error deleting secret in AWS Secret Manager", "error", err, "ripeSecret", ripe)
		}
		if deletedSecret != nil {
			jsonLogger.Info("Deleted ripe secret in AWS", "ripeSecret", *deletedSecret.Name, "date", *deletedSecret.DeletionDate)
		}
	}
}

func WriteMissingAWSSecrets(currentSecretList map[string]*api.Secret, cfg config.Config) {
	t := time.Now()
	minute := t.Minute()

	if minute > 25 && minute <= 30 || minute > 55 && minute <= 60 {
		jsonLogger.Info("checking for missing aws secrets")
		for secretName, val := range currentSecretList {
			_, found := vaultpkg.GetCustomMetadataFromSecret(val)
			awsSecretPrefix := os.Getenv("AWS_SECRET_PREFIX")
			if found && awsSecretPrefix != "" {
				extractedKeys, err := vaultpkg.ExtractCustomKeyFromCustomMetadata("AWS_ARN_REF", val)
				if err != nil {
					jsonLogger.Debug("error extracting key from custom metadata", "error", err)
					continue
				}
				if extractedKeys == nil {
					continue
				}
				correctedArns := ParseARN(extractedKeys.(string), cfg.SecretEngine, secretName)
				if len(correctedArns) > 0 {
					for _, correctedArn := range correctedArns {
						svc, err := NewAwsSecretManager(correctedArn.AccountID, cfg.AwsRole)
						if err != nil {
							jsonLogger.Error("error creating AWS Secret Manager client", "error", err)
						}
						newextractedKmsKeyId := new(string)
						extractedKmsKeyId, _ := vaultpkg.ExtractCustomKeyFromCustomMetadata("AWS_KMS_KEY", val)
						if extractedKmsKeyId != nil {
							*newextractedKmsKeyId = extractedKmsKeyId.(string)
						}

						awsPrefixSecretName := fmt.Sprintf("%s/%s", awsSecretPrefix, secretName)
						secretOutput, err := GetAwsSecret(*svc, awsPrefixSecretName)
						if err != nil {
							jsonLogger.Info("error getting secret from AWS Secret Manager", "error", err)
						}
						if secretOutput == nil {
							jsonLogger.Info("found missing secret, writing to AWS", "awsPrefixSecretName", awsPrefixSecretName)
							secretInput, err := CreateAWSSecret(*val, awsPrefixSecretName, newextractedKmsKeyId)
							if err != nil {
								jsonLogger.Info("error creating secret in AWS Secret Manager", "error", err)
							}
							err = CreateAWSSecretInManager(svc, secretInput)
							if err != nil {
								jsonLogger.Info("error creating secret in AWS Secret Manager", "error", err)
							}
						}
					}
				}
			}
		}
	}
}
