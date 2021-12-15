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
			config.Clientset = initk8sServiceAccount()
			kubernetesSecretList, err := kubernetesSecretList(config.Clientset, config.destEnv)
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Error("harvestripesecret secretlist fetch failed")
			}
			config.Clientset = initk8sServiceAccount()
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
	//e := k8sJson.NewYAMLSerializer(k8sJson.DefaultMetaFactory, nil, nil)
	e := k8sJson.NewSerializerWithOptions(k8sJson.DefaultMetaFactory, nil, nil, k8sJson.SerializerOptions{})
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
	// handle subdirectories
	subdir := ""
	subdirs := strings.Split(secretName, "/")
	// if length is 1, it means Split just returned secret name, aka no subdir
	if len(subdirs) > 1 {
		s := subdirs[:len(subdirs)-1]
		subdir = strings.Join(s, "/")
	}
	base := filepath.Join(config.clonePath, "declarative", config.destEnv, "sealedsecrets")
	createPath := filepath.Join(base, subdir)
	err := os.MkdirAll(createPath, os.ModePerm)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Fatal("ensurePathandreturnWritePath.os.Mkdir")
	}
	basePath = filepath.Join(base, secretName + ".yaml")
	return
}

func persistVaultChanges(secretList []interface{}, client *api.Client) {
	for _, secret := range secretList {

		log.WithFields(log.Fields{"secret": secret}).Debug("Checking secret")
		//make SealedSecrets
		SealedSecret, SingleKVFromVault := getKVAndCreateSealedSecret(client, newConfig, secret.(string))

		//ensure that path exists in order to write to it later.
		newBase := ensurePathandreturnWritePath(newConfig, secret.(string))
		if _, err := os.Stat(newBase); os.IsNotExist(err) {
			log.WithFields(log.Fields{"secret": secret.(string), "action": "request.operation.create"}).Info("Creating Sealed Secret")
			SerializeAndWriteToFile(SealedSecret, newBase)
			initKubernetesSearch(secret.(string), newConfig)
		} else if !readSealedSecretAndCompareWithVaultStruct(secret.(string), SingleKVFromVault, newBase, newConfig.secretEngine) {
			log.WithFields(log.Fields{"secret": secret, "action": "request.operation.compare"}).Debug("readSealedSecretAndCompare: we already have this secret. Vault did not update")
		} else {
			// we need to update the secret.
			log.WithFields(log.Fields{"secret": secret, "newBase": newBase, "action": "request.operation.update"}).Info("readSealedSecretAndCompare: updating secret")
			SerializeAndWriteToFile(SealedSecret, newBase)
			initKubernetesSearch(secret.(string), newConfig)
		}

	}
}
