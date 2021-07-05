package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	sealedSecretPkg "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	log "github.com/sirupsen/logrus"
	k8sJson "k8s.io/apimachinery/pkg/runtime/serializer/json"
)

/*
HarvestRipeSecrets() checks local files based on RipeSecrets returned from PickRipeSecrets() and marks them for deletion.

*/
func HarvestRipeSecrets(RipeSecrets []string, config config) {
	if len(RipeSecrets) == 0 {
	} else {

		r, err := git.PlainOpen(config.clonePath)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Info("HarvestRipeSecrets plainopen failed")
		}

		w, err := r.Worktree()
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Error("HarvestRipeSecrets worktree failed")
		}
		//Iterate ripe secrets and remove them from worktree and push changes.
		for ripe := range RipeSecrets {
			base := filepath.Join("declarative", config.destEnv, "sealedsecrets")
			newbase := base + "/" + RipeSecrets[ripe] + ".yaml"
			_, err = w.Remove(newbase)
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Error("HarvestRipeSecrets worktree.Remove failed")
			}
			log.WithFields(log.Fields{"ripeSecret": RipeSecrets[ripe]}).Info("HarvestRipeSecrets found ripe secret. marked for deletion")
		}
		status, err := w.Status()

		if err != nil {
			log.WithFields(log.Fields{
				"err": err,
			}).Error("HarvestRipeSecret Worktree status failed")
		}

		if !status.IsClean() {

			log.WithFields(log.Fields{"worktree": w, "status": status}).Debug("HarvestRipeSecret !status.IsClean() ")

			commit, err := w.Commit(fmt.Sprintf("Raven removed ripe secret from git"), &git.CommitOptions{
				Author: &object.Signature{
					Name:  "Raven",
					Email: "itte@tæll.no",
					When:  time.Now(),
				},
			})

			if strings.HasPrefix(newConfig.repoUrl, "ssh:") {
				err = r.Push(&git.PushOptions{Auth: setSSHConfig()})
				if err != nil {
					panic(err)
				}
			} else {
				err = r.Push(&git.PushOptions{})
				if err != nil {
					log.WithFields(log.Fields{"error": err}).Error("Raven gitPush error")
				}
				// Prints the current HEAD to verify that all worked well.
				obj, err := r.CommitObject(commit)

				if err != nil {
					log.WithFields(log.Fields{"obj": obj}).Error("git show -s")
				}
				log.WithFields(log.Fields{"obj": obj}).Info("git show -s: commit")
				genericPostWebHook()
			}

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