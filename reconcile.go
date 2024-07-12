package main

import (
	"fmt"
	sealedSecretPkg "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
	k8sJson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"os"
	"path/filepath"
	"strings"
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
			log.WithFields(log.Fields{"err": err}).Error("HarvestRipeSecret Worktree status failed")
		}

		if !status.IsClean() {
			log.WithFields(log.Fields{"worktree": worktree, "status": status}).Debug("HarvestRipeSecret !status.IsClean() ")
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
				log.WithFields(log.Fields{"err": err}).Error("harvestripesecret secretlist fetch failed")
			}
			config.Clientset = NewKubernetesClient()
			kubernetesRemove(RipeSecrets, kubernetesSecretList, config.Clientset, config.destEnv)
			log.WithFields(log.Fields{}).Debug("HarvestRipeSecrets done")
		}
	}
}

func SerializeAndWriteToFile(SealedSecret *sealedSecretPkg.SealedSecret, fullPath string) {

	f, err := os.Create(fullPath)
	if err != nil {
		log.WithFields(log.Fields{"fullPath": fullPath, "error": err.Error()}).Fatal("SerializeAndWriteToFile.Os.Create")
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
		log.WithFields(log.Fields{"fullPath": fullPath, "error": err.Error()}).Fatal("SerializeAndWriteToFile.e.encode")
		WriteErrorToTerminationLog(err.Error())
	}

}

/*
ensurePathandreturnWritePath:
* build stringpath
* create path

makes sure that basePath exists for SerializeAndWriteToFile, returning basePath.
*/

func ensurePathandreturnWritePath(config config, secretName string) (basePath string) {
	base := filepath.Join(config.clonePath, "declarative", config.destEnv, "sealedsecrets")
	err := os.MkdirAll(base, os.ModePerm)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Fatal("ensurePathandreturnWritePath.os.Mkdir")
	}
	if strings.HasSuffix(secretName, "/") {
		fmt.Println("need to replace strings here", secretName)
		secretName = strings.Replace(secretName, "/", "", -1)
	}
	basePath = base + "/" + secretName + ".yaml"
	return
}

func persistVaultChanges(secretList []interface{}, client *api.Client, config config) {
	if secretList != nil {
		for _, secret := range secretList {
			log.WithFields(log.Fields{"secret": secret}).Debug("Checking secret")
			input := fmt.Sprintf("%s/", config.secretEngine)
			iterateList(input, client, secret.(string))
		}
		if mySecretList != nil {
			for path, val := range mySecretList {
				log.WithFields(log.Fields{"SingleKVFromVault": val}).Debug("getKVAndCreateSealedSecret.SingleKVFromVault")
				k8sSecret := createK8sSecret(path, config, val)
				SealedSecret := createSealedSecret(config.pemFile, &k8sSecret)

				err := WriteAWSKeyValueSecret(val, path)
				if err != nil {
					log.WithFields(log.Fields{"error": err, "secret": val}).Debug("persistVaultChanges.WriteAWSKeyValueSecret")
				}
				newBase := ensurePathandreturnWritePath(newConfig, SealedSecret.Name)
				if _, err := os.Stat(newBase); os.IsNotExist(err) {
					log.WithFields(log.Fields{"secret": SealedSecret.Name, "action": "request.operation.create"}).Info("Creating Sealed Secret")
					SerializeAndWriteToFile(SealedSecret, newBase)
					initKubernetesSearch(path, newConfig)
				} else if !readSealedSecretAndCompareWithVaultStruct(SealedSecret.Name, val, newBase, newConfig.secretEngine) {
					log.WithFields(log.Fields{"secret": val, "action": "request.operation.compare"}).Debug("readSealedSecretAndCompare: we already have this secret. Vault did not update")
				} else {
					// we need to update the secret.
					log.WithFields(log.Fields{"secret": SealedSecret, "newBase": newBase, "action": "request.operation.update"}).Info("readSealedSecretAndCompare: updating secret")
					SerializeAndWriteToFile(SealedSecret, newBase)
					initKubernetesSearch(SealedSecret.Name, newConfig)
				}

			}
		} else {
			fmt.Println("mysecretList empty")
		}

	} else {
		fmt.Println("secret list is empty")
	}

}
