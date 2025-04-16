package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	sealedSecretPkg "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
	"github.com/hashicorp/vault/api"
	k8sJson "k8s.io/apimachinery/pkg/runtime/serializer/json"
)

/*
HarvestRipeSecrets() checks local files based on RipeSecrets returned from PickRipeSecrets() and marks them for deletion.
*/
func HarvestRipeSecrets(RipeSecrets []string, config config) {
	if len(RipeSecrets) > 0 {
		repo := InitializeGitRepo(config)
		worktree := initializeWorkTree(repo)
		removeFromWorkingtree(RipeSecrets, worktree, config)
		status, err := getGitStatus(worktree)
		if err != nil {
			jsonLogger.Error("HarvestRipeSecret Worktree status failed", "error", err)
		}

		if !status.IsClean() {
			jsonLogger.Debug("HarvestRipeSecret !status.IsClean()", "worktree", worktree, "status", status)
			commitMessage := fmt.Sprintf("Raven removed ripe secret(s) from git")
			commit, _ := makeCommit(worktree, commitMessage)
			setPushOptions(config, repo, commit)
			logHarvestDone(repo, commit)
		}
		kubernetesremove := os.Getenv("KUBERNETESREMOVE")
		if kubernetesremove == "true" {
			config.Clientset = NewKubernetesClient()
			kubernetesSecretList, err := kubernetesSecretList(config.Clientset, config.destEnv)
			if err != nil {
				jsonLogger.Error("harvestripesecret secretlist fetch failed", "error", err)
			}
			config.Clientset = NewKubernetesClient()
			kubernetesRemove(RipeSecrets, kubernetesSecretList, config.Clientset, config.destEnv)
			jsonLogger.Info("HarvestRipeSecrets done")
		}
	}
}

func SerializeSealedSecretToFile(SealedSecret *sealedSecretPkg.SealedSecret, fullPath string) {

	f, err := os.Create(fullPath)
	if err != nil {
		jsonLogger.Error("SerializeSealedSecretToFile.Os.Create", "error", err)
		WriteErrorToTerminationLog(err.Error())
	}

	options := k8sJson.SerializerOptions{
		Yaml:   true,
		Pretty: true,
		Strict: true,
	}
	e := k8sJson.NewSerializerWithOptions(k8sJson.DefaultMetaFactory, nil, nil, options)
	err = e.Encode(SealedSecret, f)
	if err != nil {
		jsonLogger.Error("SerializeSealedSecretToFile encoding error", "error", err)
		WriteErrorToTerminationLog(err.Error())
	}

}

/*
ensurePathAndReturnWritePath:
* build stringpath
* create path

makes sure that basePath exists for SerializeSealedSecretToFile, returning basePath.
*/

func ensurePathAndReturnWritePath(config config, secretName string) (basePath string) {
	base := filepath.Join(config.clonePath, "declarative", config.destEnv, "sealedsecrets")
	err := os.MkdirAll(base, os.ModePerm)
	if err != nil {
		jsonLogger.Error("ensurePathAndReturnWritePath.os.Mkdir", "error", err)
	}
	if strings.HasSuffix(secretName, "/") {
		fmt.Println("need to replace strings here", secretName)
		secretName = strings.Replace(secretName, "/", "", -1)
	}
	basePath = base + "/" + secretName + ".yaml"
	return
}

func synchronizeVaultSecrets(secretList []interface{}, client *api.Client, theConfig config) {
	if secretList != nil {
		for _, secret := range secretList {
			jsonLogger.Debug("Checking secret", "secret", secret)
			input := fmt.Sprintf("%s/", theConfig.secretEngine)
			iterateList(input, client, secret.(string))
		}
		if currentSecrets != nil {
			for path, theVaultSecret := range currentSecrets {
				jsonLogger.Debug("getKVAndCreateSealedSecret", "path", path, "theVaultSecret", theVaultSecret)
				NoSync, err := ExtractCustomKeyFromCustomMetadata("NO_SYNC", theVaultSecret)
				if err != nil {
					jsonLogger.Debug("synchronizeVaultSecrets.ExtractCustomKeyFromCustomMetadata", "error", err)
				}
				if NoSync != nil {
					jsonLogger.Debug("synchronizeVaultSecrets: NO_SYNC is set for secret. Skipping", "secret", path)
					continue
				} else {

					k8sSecret := createK8sSecret(path, theConfig, theVaultSecret)
					SealedSecret := createSealedSecret(theConfig.pemFile, &k8sSecret)

					newBase := ensurePathAndReturnWritePath(theConfig, SealedSecret.Name)
					if _, err := os.Stat(newBase); os.IsNotExist(err) {
						jsonLogger.Info("Creating Sealed Secret", slog.String("action", "request.operation.create"), slog.String("secret", SealedSecret.Name))
						SerializeSealedSecretToFile(SealedSecret, newBase)
						if theConfig.awsWriteback == true {
							err := WriteAWSKeyValueSecret(theVaultSecret, path, theConfig)
							if err != nil {
								jsonLogger.Error("synchronizeVaultSecrets.WriteAWSKeyValueSecret", "error", err)
							}
						} else {
							jsonLogger.Debug("AWS_WRITEBACK not set")
						}
						KubernetesNotificationUrl := os.Getenv("KUBERNETES_NOTIFICATION_WEBHOOK_URL")
						if KubernetesNotificationUrl != "" {
							msgTitle := "Raven created sealed secret in git"
							msgBody := fmt.Sprintf("created sealed secret in git: %s", SealedSecret.Name)
							NotifyTeamsChannel(msgTitle, msgBody, KubernetesNotificationUrl)
						}
						initKubernetesSearch(path, theConfig)
					} else if !readSealedSecretAndCompareWithVaultStruct(theVaultSecret, newBase, theConfig.secretEngine) {
						jsonLogger.Debug("readSealedSecretAndCompare: we already have this secret. Vault did not update", slog.String("secret", SealedSecret.Name))
					} else {
						// we need to update the secret.
						jsonLogger.Info("Updating Sealed Secret", slog.String("action", "request.operation.update"), slog.String("secret", SealedSecret.Name))
						SerializeSealedSecretToFile(SealedSecret, newBase)
						if theConfig.awsWriteback == true {
							// describe aws secret
							//  aws.getsecret()
							// write
							err := WriteAWSKeyValueSecret(theVaultSecret, path, theConfig)
							if err != nil {
								jsonLogger.Error("synchronizeVaultSecrets.WriteAWSKeyValueSecret", slog.Any("error", err))
							}
						} else {
							jsonLogger.Debug("AWS_WRITEBACK not set")
						}
						KubernetesNotificationUrl := os.Getenv("KUBERNETES_NOTIFICATION_WEBHOOK_URL")
						if KubernetesNotificationUrl != "" {
							msgTitle := "Raven updated sealed secret in git"
							msgBody := fmt.Sprintf("created sealed secret in git: %s", SealedSecret.Name)
							NotifyTeamsChannel(msgTitle, msgBody, KubernetesNotificationUrl)
						}
						initKubernetesSearch(SealedSecret.Name, theConfig)
					}

				}
			}
		} else {
			jsonLogger.Info("currentSecrets is nil")
		}

	} else {
		jsonLogger.Info("secretList is nil")
	}

}
