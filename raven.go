package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/hashicorp/vault/api"

	log "github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	"path/filepath"
	"strings"
)

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

func createK8sSecret(name string, config config, dataFields *api.Secret) (secret v1.Secret) {

	Annotations := applyAnnotations(dataFields, config)
	data, stringdata := applyDatafieldsTok8sSecret(dataFields, config, Annotations)
	Annotations = applyMetadata(dataFields, config, Annotations)

	SecretContent := SecretContents{stringdata: stringdata, data: data, Annotations: Annotations, name: name}
	secret = NewSecretWithContents(SecretContent, config)

	log.WithFields(log.Fields{"typeMeta": secret.TypeMeta, "objectMeta": secret.ObjectMeta, "data": data, "stringData": stringdata, "secret": secret}).Debug("createK8sSecret: made k8s secret object")
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
		client, err := client()
		if err != nil {
			log.WithFields(log.Fields{"config": newConfig}).Fatal("failed to initialize client")

		}
		if validateSelftoken(client) {

			// start webserver
			go handleRequests()

			//ensure paths for first time.
			newpath := filepath.Join(*clonePath, *secretEngine)
			err := os.MkdirAll(newpath, os.ModePerm)
			if err != nil {
				log.WithFields(log.Fields{"NewPath": newpath}).Error("os.Mkdir failed when trying to ensure paths for first time")
				WriteErrorToTerminationLog("os.Mkdir failed when trying to ensure paths for first time")
			}

			GitClone(newConfig)
			last := &api.Secret{}
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("client not initialized")

			}
			for {
				if validateSelftoken(client) {
					log.WithFields(log.Fields{}).Debug("Validated Token: grabbing list of secrets")
					var list, err = getAllKVs(client, newConfig)
					if err != nil {
						log.WithFields(log.Fields{"error": err}).Error("getAllKVs list error")
					}
					if list == nil {
						cleanDeadEntries()
					} else {
						secretList := list.Data["keys"].([]interface{})
						persistVaultChanges(secretList, client)
						//..and push new files if there were any. If there are any ripe secrets, delete.
						PickedRipeSecrets := PickRipeSecrets(last, list)
						HarvestRipeSecrets(PickedRipeSecrets, newConfig)
						gitPush(newConfig)
						log.WithFields(log.Fields{"PickedRipeSecrets": PickedRipeSecrets}).Debug("PickedRipeSecrets list")

						// we save last state of previous list.
						last = list
						sleep()
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
