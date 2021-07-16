package main

import (
	sealedSecretPkg "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
	log "github.com/sirupsen/logrus"
	k8sJson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"os"
	"path/filepath"
)

/*
HarvestRipeSecrets() checks local files based on RipeSecrets returned from PickRipeSecrets() and marks them for deletion.

*/
func HarvestRipeSecrets(RipeSecrets []string, config config) {
	if len(RipeSecrets) == 0 {
	} else {

		repo := InitializeGitRepo(config)
		worktree := initializeWorkTree(repo)
		iterateRipeSecretsAndRemoveFromWorkingtree(RipeSecrets, worktree, config)
		status, err := getGitStatus(worktree)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Error("HarvestRipeSecret Worktree status failed")
		}

		if !status.IsClean() {
			log.WithFields(log.Fields{"worktree": worktree, "status": status}).Debug("HarvestRipeSecret !status.IsClean() ")
			commit, _ := makeCommit(worktree)
			setPushOptions(config, repo, commit)
		}
		log.WithFields(log.Fields{}).Debug("HarvestRipeSecrets done")
	}
}

func SerializeAndWriteToFile(SealedSecret *sealedSecretPkg.SealedSecret, fullPath string) {
	f, err := os.Create(fullPath)
	if err != nil {
		log.WithFields(log.Fields{"fullPath": fullPath, "error": err.Error()}).Fatal("SerializeAndWriteToFile.Os.Create")
		WriteErrorToTerminationLog(err.Error())
	}
	e := k8sJson.NewYAMLSerializer(k8sJson.DefaultMetaFactory, nil, nil)
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

func ensurePathandreturnWritePath(clonePath string, destEnv string, secretName string) (basePath string) {
	base := filepath.Join(clonePath, "declarative", destEnv, "sealedsecrets")
	os.MkdirAll(base, os.ModePerm)
	basePath = base + "/" + secretName + ".yaml"
	return
}
