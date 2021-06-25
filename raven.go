package main

import (
	"encoding/base64"
	"flag"
	"fmt"

	"io/ioutil"
	"math/rand"
	"os"

	git "github.com/go-git/go-git/v5"
	"github.com/hashicorp/vault/api"

	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/go-git/go-git/v5/plumbing/object"
	log "github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type config struct {
	vaultEndpoint     string
	secretEngine      string
	token             string
	destEnv           string
	pemFile           string
	clonePath         string
	repoUrl           string
	DocumentationKeys []string
}

func init() {
	// Log as JSON instead of the default ASCII formatter.
	log.SetFormatter(&log.JSONFormatter{})

	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	log.SetOutput(os.Stdout)

	loglevel := os.Getenv("LOGLEVEL")

	switch {
	case loglevel == "INFO":
		log.SetLevel(log.InfoLevel)
		log.Infof("Loglevel is: %v", loglevel)
	case loglevel == "DEBUG":
		log.SetLevel(log.DebugLevel)
		log.Infof("Loglevel is: %v", loglevel)
	default:
		log.SetLevel(log.InfoLevel)
		log.Info("No LOGLEVEL specified. Defaulting to Info")

	}

}

/*/

isDocumentationKey parses documentationKeys list, returns true if key exists.
*/
func isDocumentationKey(DocumentationKeys []string, key string) bool {
	for _, DocumentationKey := range DocumentationKeys {
		if DocumentationKey == key {
			log.WithFields(log.Fields{"key": key, "DocumentationKeys": DocumentationKeys}).Debug("IsdocumentationKey found key")
			return true
		}
	}
	return false
}

/*
initAdditionalKeys looks for DOCUMENTATION_KEYS in order to enrich secret object with annotation down the line.
*/

func initAdditionalKeys() (DocumentationKeys []string) {
	keys := os.Getenv("DOCUMENTATION_KEYS")
	DocumentationKeys = strings.Split(keys, ",")

	if !isDocumentationKey(DocumentationKeys, "raven/description") {
		DocumentationKeys = append(DocumentationKeys, "raven/description")
		log.WithFields(log.Fields{"DocumentationKeys": DocumentationKeys}).Info("No documentation_KEYS found, setting raven/description")

	}

	return
}

/*
   We assume program crashed and we need to tell Kubernetes this:
   https://kubernetes.io/docs/tasks/debug-application-cluster/determine-reason-pod-failure/
*/

func WriteErrorToTerminationLog(errormsg string) {
	file, _ := os.Create("/dev/termination-log")
	defer file.Close()

	file.WriteString(errormsg)

}

/*
   Alive checks for differences between two arrays
*/

func Alive(slice []interface{}, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

/*
scaffolding for k8s,
createK8sSecret generates k8s secrets based on inputs:
- name: name of secret
- Namespace: k8s namespace
- datafield: data for secret
returns v1.Secret for consumption by SealedSecret
*/

func createK8sSecret(name string, Namespace string, sourceenv string, dataFields *api.Secret) (secret v1.Secret) {
	Annotations := make(map[string]string)
	for k, v := range dataFields.Data["metadata"].(map[string]interface{}) {
		switch v.(type) {
		case float64:
			float64value := reflect.ValueOf(v)
			float64convert := strconv.FormatFloat(float64value.Float(), 'f', -1, 64)
			Annotations[k] = float64convert
		case string:
			Annotations[k] = v.(string)
		case bool:
			booleanvalue := reflect.ValueOf(v)
			boolconvert := strconv.FormatBool(booleanvalue.Bool())
			Annotations[k] = boolconvert
		}
	}

	stringdata := make(map[string]string)
	data := make(map[string][]byte)
	isbase64 := func(s string) bool {
		_, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return false
		}
		return true
	}
	Annotations["source"] = sourceenv
	if dataFields.Data["data"] == nil {
		log.WithFields(log.Fields{"secret": name}).Info("secret has no data defined in body. skipping it.")
	} else {
		for k, v := range dataFields.Data["data"].(map[string]interface{}) {
			log.WithFields(log.Fields{"key": k, "value": v, "datafields": dataFields.Data["data"]}).Debug("createK8sSecret: dataFields.Data[data] iterate")
			if strings.HasPrefix(v.(string), "base64:") {
				stringSplit := strings.Split(v.(string), ":")
				if isbase64(stringSplit[1]) {
					data[k], _ = base64.StdEncoding.DecodeString(stringSplit[1])

					log.WithFields(log.Fields{"key": k, "value": v, "split": stringSplit, "datafields": dataFields.Data["data"]}).Debug("createK8sSecret: dataFields.Data[data] found base64-encoding")
				} else {
					log.WithFields(log.Fields{"key": k, "value": v}).Warn("key is not valid BASE64")
				}
			} else if isDocumentationKey(newConfig.DocumentationKeys, k) {
				Annotations[k] = v.(string)
				log.WithFields(log.Fields{"key": k, "value": v, "datafields": dataFields.Data["data"], "Annotations": Annotations}).Debug("createK8sSecret: dataFields.Data[data] found description field")
			} else {
				stringdata[k] = v.(string)
				log.WithFields(log.Fields{"key": k, "value": v, "datafields": dataFields.Data["data"]}).Debug("createK8sSecret: dataFields.Data[data] catch all. putting value in stringdata[]")
			}
		}
	}
	if dataFields.Data["metadata"] == nil {
		log.WithFields(log.Fields{"secret": name}).Info("secret has no metadata defined in body. skipping it.")
	} else {
		for k, v := range dataFields.Data["metadata"].(map[string]interface{}) {
			// we handle descriptions for KVs here, in order to show which secrets are handled by which SSG.
			switch v.(type) {
			case float64:

				float64value := reflect.ValueOf(v)
				float64convert := strconv.FormatFloat(float64value.Float(), 'f', -1, 64)
				Annotations[k] = float64convert
				log.WithFields(log.Fields{"key": k, "value": v, "datafields": dataFields.Data["metadata"]}).Debug("createK8sSecret: dataFields.Data[metadata] case match float64 ")
			case string:
				Annotations[k] = v.(string)
				log.WithFields(log.Fields{"key": k, "value": v, "datafields": dataFields.Data["metadata"]}).Debug("createK8sSecret: dataFields.Data[metadata] case match string ")
			case bool:
				booleanvalue := reflect.ValueOf(v)
				boolconvert := strconv.FormatBool(booleanvalue.Bool())
				Annotations[k] = boolconvert
				log.WithFields(log.Fields{"key": k, "value": v, "datafields": dataFields.Data["metadata"]}).Debug("createK8sSecret: dataFields.Data[metadata] case match bool ")
			}

		}
	}

	secret = v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SealedSecret",
			APIVersion: "bitnami.com/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   Namespace,
			Annotations: Annotations,
		},
		Data:       data,
		StringData: stringdata,
		Type:       "Opaque",
	}

	log.WithFields(log.Fields{"typeMeta": secret.TypeMeta, "objectMeta": secret.ObjectMeta, "data": data, "stringData": stringdata, "secret": secret}).Info("createK8sSecret: made k8s secret object")
	return
}

var newConfig = config{
	vaultEndpoint:     "",
	secretEngine:      "",
	token:             "",
	destEnv:           "",
	pemFile:           "",
	clonePath:         "",
	repoUrl:           "",
	DocumentationKeys: initAdditionalKeys(),
}

func main() {
	token := flag.String("token", "", "token used for to grab secrets from Vault")
	secretEngine := flag.String("se", "", "specifies secret engine to grab secrets from in Vault")
	vaultEndpoint := flag.String("vaultendpoint", "", "URL to the Vault installation.")
	pemFile := flag.String("cert", "", "used to create sealed secrets")
	repoUrl := flag.String("repourl", "", "REPO url. e.g. https://uname:pwd@src_control/some/path/somerepo.git")
	clonePath := flag.String("clonepath", "/tmp/clone", "Path in which to clone repo and used for base for appending keys.")
	destEnv := flag.String("dest", "", "destination env in git repository to output SealedSecrets to.")
	flag.Parse()

	visited := true
	flag.VisitAll(func(f *flag.Flag) {
		if f.Value.String() == "" {
			fmt.Printf("[*] -%s not set. Quitting [*]\n", f.Name)
			visited = false
		}

	})
	if visited {
		newConfig.vaultEndpoint = *vaultEndpoint
		newConfig.secretEngine = *secretEngine
		newConfig.token = *token
		newConfig.destEnv = *destEnv
		newConfig.pemFile = *pemFile
		newConfig.clonePath = *clonePath
		newConfig.repoUrl = *repoUrl
		newConfig.DocumentationKeys = initAdditionalKeys() // we make sure that if the env here is set we can allow multiple descriptional fields in annotations.

		log.WithFields(log.Fields{"config": newConfig}).Debug("Setting newConfig variables. preparing to run. ")
		if validateSelftoken(*vaultEndpoint, *token) {

			// start webserver
			go handleRequests()

			//ensure paths for first time.
			newpath := filepath.Join(*clonePath, *secretEngine)
			err := os.MkdirAll(newpath, os.ModePerm)
			if err != nil {
				log.WithFields(log.Fields{"NewPath": newpath}).Error("os.Mkdir failed when trying to ensure paths for first time")
				WriteErrorToTerminationLog("os.Mkdir failed when trying to ensure paths for first time")
			}

			GitClone(*clonePath, *repoUrl)
			last := &api.Secret{}
			for {
				if validateSelftoken(*vaultEndpoint, *token) {
					log.WithFields(log.Fields{}).Debug("Validated Token: grabbing list of secrets")

					var list, err = getAllKVs(newConfig.secretEngine, newConfig.token)
					if err != nil {
						log.WithFields(log.Fields{"error": err}).Error("getAllKVs list error")
					}
					if list == nil {
						log.Info("list is nil. We should check if we have a directory full of files that should be deleted from git.")

						base := filepath.Join(newConfig.clonePath, "declarative", newConfig.destEnv, "sealedsecrets")
						files, err := ioutil.ReadDir(base)
						if err != nil {
							log.WithFields(log.Fields{"error": err}).Error("ioutil.ReadDir() error")
						}

						r, err := git.PlainOpen(newConfig.clonePath)
						if err != nil {
							log.WithFields(log.Fields{"err": err}).Info("HarvestRipeSecrets plainopen failed")
						}
						w, err := r.Worktree()
						if err != nil {
							log.WithFields(log.Fields{"err": err}).Info("HarvestRipeSecrets worktree failed")
						}
						if len(files) > 0 {
							for _, f := range files {
								base := filepath.Join("declarative", newConfig.destEnv, "sealedsecrets")
								newbase := base + "/" + f.Name()
								_, err = w.Remove(newbase)
								if err != nil {
									log.WithFields(log.Fields{"err": err}).Error("HarvestRipeSecrets worktree.Remove failed")
								}
								log.WithFields(log.Fields{"path": newbase, "ripeSecret": f.Name()}).Info("HarvestRipeSecrets found ripe secret. marked for deletion")

							}
							status, err := w.Status()
							if err != nil {
								log.WithFields(log.Fields{"status": status}).Info("Worktree.status failed")
							}

							if !status.IsClean() {

								log.WithFields(log.Fields{"worktree": w, "status": status}).Info("HarvestRipeSecret !status.IsClean() ")

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
									fmt.Println("head: ", obj)

									if err != nil {
										log.WithFields(log.Fields{"obj": obj}).Error("git show -s")
									}
									log.WithFields(log.Fields{"obj": obj}).Info("git show -s: commit")
									genericPostWebHook()
								}
							}
						}
						log.Info("Going to sleep now.")
						time.Sleep(30 * time.Second)
					} else {
						for _, secret := range list.Data["keys"].([]interface{}) {

							log.WithFields(log.Fields{"secret": secret}).Debug("Checking secret")
							//make SealedSecrets
							SealedSecret, SingleKVFromVault := getKVAndCreateSealedSecret(newConfig.secretEngine, secret.(string), newConfig.token, newConfig.destEnv, newConfig.pemFile)

							//ensure that path exists in order to write to it later.
							newBase := ensurePathandreturnWritePath(*clonePath, *destEnv, secret.(string))
							if _, err := os.Stat(newBase); os.IsNotExist(err) {
								log.WithFields(log.Fields{"SealedSecret": secret.(string)}).Info(`Creating Sealed Secret`)
								SerializeAndWriteToFile(SealedSecret, newBase)
							} else if !readSealedSecretAndCompareWithVaultStruct(secret.(string), SingleKVFromVault, newBase, newConfig.secretEngine) {
								log.WithFields(log.Fields{"secret": secret}).Debug("readSealedSecretAndCompare: we already have this secret. Vault did not update")
							} else {
								// we need to update the secret.
								log.WithFields(log.Fields{"SealedSecret": secret, "newBase": newBase}).Info("readSealedSecretAndCompare: Found new secret, need to create new sealed secret file")
								SerializeAndWriteToFile(SealedSecret, newBase)
							}

						}
						//..and push new files if there were any. If there are any ripe secrets, delete.
						PickedRipeSecrets := PickRipeSecrets(last, list)
						HarvestRipeSecrets(PickedRipeSecrets, newConfig.clonePath, newConfig.destEnv)
						gitPush(newConfig.clonePath, newConfig.destEnv, *repoUrl)
						log.WithFields(log.Fields{"PickedRipeSecrets": PickedRipeSecrets}).Debug("PickedRipeSecrets list")

						// we save last state of previous list.
						last = list

						// calculate random sleep between 15 and 30 seconds
						rand.Seed(time.Now().UnixNano())
						max := 30
						min := 15
						sleepTime := rand.Intn(max-min) + min

						//now we sleep randomly
						log.WithFields(log.Fields{"sleepTime": sleepTime}).Debug("Going to sleep.")
						time.Sleep(time.Duration(sleepTime) * time.Second)
						log.WithFields(log.Fields{"sleepTime": sleepTime}).Debug("Sleep done.")

					}
				}
			}
		} else {
			log.WithFields(log.Fields{"token": token}).Warn("Token is invalid, need to update. ")
			WriteErrorToTerminationLog("[*] token is invalid, someone needs to update this![*]")
			os.Exit(1)
		}
	}
}
