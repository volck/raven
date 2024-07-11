package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/hashicorp/vault/api"

	log "github.com/sirupsen/logrus"
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
	token := flag.String("token", os.Getenv("VAULT_TOKEN"), "token used for to grab secrets from Vault")
	secretEngine := flag.String("se", os.Getenv("SECRET_ENGINE"), "specifies secret engine to grab secrets from in Vault")
	vaultEndpoint := flag.String("vaultendpoint", os.Getenv("VAULTENDPOINT"), "URL to the Vault installation.")
	pemFile := flag.String("cert", os.Getenv("CERT_FILE"), "used to create sealed secrets")
	repoUrl := flag.String("repourl", os.Getenv("REPO_URL"), "REPO url. e.g. https://uname:pwd@src_control/some/path/somerepo.git")
	clonePath := flag.String("clonepath", os.Getenv("CLONE_PATH"), "Path in which to clone repo and used for base for appending keys.")
	destEnv := flag.String("dest", os.Getenv("DEST_ENV"), "destination env in git repository to output SealedSecrets to.")
	sleepTime := flag.Int("sleep", getIntEnv("SLEEP_TIME", 360), "define how long Raven should sleep between each iteration")
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

		kubernetesMonitor := os.Getenv("KUBERNETESMONITOR")
		kubernetesRemove := os.Getenv("KUBERNETESREMOVE")
		kubernetesDoRollout := os.Getenv("KUBERNETES_ROLLOUT")

		if kubernetesMonitor == "true" || kubernetesRemove == "true" {
			newConfig.Clientset = NewKubernetesClient()
		}

		if kubernetesDoRollout == "true" {
			theLogger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
			newClient := NewKubernetesClient()
			w := NewWatcher(theLogger, newClient, *destEnv)
			sufficientPermissions := w.CheckKubernetesServiceAccountPermissions()
			if sufficientPermissions {
				w.MonitorNamespaceForSecretChange()
			} else {
				w.Logger.Info("ServiceAccount does not have permissions to watch namespace, exiting go routine")
			}
		}

		log.WithFields(log.Fields{"config": newConfig}).Debug("Setting newConfig variables. preparing to run. ")
		client, err := client()
		if err != nil {
			log.WithFields(log.Fields{"config": newConfig}).Fatal("failed to initialize client")

		}

		if validToken(client) {
			// start webserver
			go handleRequests(newConfig)
			//ensure paths for first time.
			newpath := filepath.Join(*clonePath, *secretEngine)
			err := os.MkdirAll(newpath, os.ModePerm)
			if err != nil {
				log.WithFields(log.Fields{"NewPath": newpath}).Error("os.Mkdir failed when trying to ensure paths for first time")
				WriteErrorToTerminationLog("os.Mkdir failed when trying to ensure paths for first time")
			}

			GitClone(newConfig)
			State := map[string]*api.Secret{}
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("client not initialized")
			}
			for {
				if validToken(client) {
					log.WithFields(log.Fields{}).Debug("Validated Token: grabbing list of secrets")
					var list, err = getAllKVs(client, newConfig)
					if err != nil {
						log.WithFields(log.Fields{"error": err}).Error("getAllKVs list error")
					}
					if list == nil {
						cleanDeadEntries()
					} else {
						mySecretList = map[string]*api.Secret{}
						secretList := list.Data["keys"].([]interface{})
						persistVaultChanges(secretList, client, newConfig)
						//..and push new files if there were any. If there are any ripe secrets, delete.
						PickedRipeSecrets := PickRipeSecrets(State, mySecretList)
						HarvestRipeSecrets(PickedRipeSecrets, newConfig)
						gitPush(newConfig)
						log.WithFields(log.Fields{"PickedRipeSecrets": PickedRipeSecrets}).Debug("PickedRipeSecrets list")
						State = mySecretList
						sleep(*sleepTime)
					}
				}
			}
		} else {
			log.WithFields(log.Fields{"token": token}).Warn("Token is invalid, need to update. ")
			WriteErrorToTerminationLog("[*] token is invalid, someone needs to update this![*]")
		}
	}
}
