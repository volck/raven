package main

import (
	"flag"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/hashicorp/vault/api"

	log "github.com/sirupsen/logrus"
)

var cfgFile string
var newConfig config

var rootCmd = &cobra.Command{
	Use:   "raven",
	Short: "Raven is a tool for managing secrets",
	Long:  `Raven is a CLI tool for managing secrets in Vault and synchronizing them across different environments.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := initializeConfig()
		startRaven(cfg)
	},
}

func init() {
	cobra.OnInitialize(initConfig)

	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)

	rootCmd.Flags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.raven.yaml)")

	rootCmd.Flags().String("token", "", "token used for to grab secrets from Vault")
	rootCmd.Flags().String("se", "", "specifies secret engine to grab secrets from in Vault")
	rootCmd.Flags().String("vaultendpoint", "", "URL to the Vault installation.")
	rootCmd.Flags().String("cert", "", "used to create sealed secrets")
	rootCmd.Flags().String("repourl", "", "REPO url.")
	rootCmd.Flags().String("clonepath", "", "Path in which to clone repo and used for base for appending keys.")
	rootCmd.Flags().String("dest", "", "destination env in git repository to output SealedSecrets to.")
	rootCmd.Flags().String("loglevel", "INFO", "loglevel")
	rootCmd.Flags().Int("sleep", 360, "define how long Raven should sleep between each iteration")

	// setting required flags
	//rootCmd.MarkFlagRequired("token")
	//rootCmd.MarkFlagRequired("se")
	//rootCmd.MarkFlagRequired("vaultendpoint")
	//rootCmd.MarkFlagRequired("cert")
	//rootCmd.MarkFlagRequired("repourl")
	//rootCmd.MarkFlagRequired("clonepath")
	//rootCmd.MarkFlagRequired("dest")

	viper.BindPFlag("token", rootCmd.Flags().Lookup("token"))
	viper.BindPFlag("secretEngine", rootCmd.Flags().Lookup("se"))
	viper.BindPFlag("vaultEndpoint", rootCmd.Flags().Lookup("vaultendpoint"))
	viper.BindPFlag("pemFile", rootCmd.Flags().Lookup("cert"))
	viper.BindPFlag("repoUrl", rootCmd.Flags().Lookup("repourl"))
	viper.BindPFlag("clonePath", rootCmd.Flags().Lookup("clonepath"))
	viper.BindPFlag("loglevel", rootCmd.Flags().Lookup("clonepath"))
	viper.BindPFlag("destEnv", rootCmd.Flags().Lookup("dest"))
	viper.BindPFlag("sleepTime", rootCmd.Flags().Lookup("sleep"))

	viper.AutomaticEnv()
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

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Println(err)
		}
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".raven")
	}

	viper.ReadInConfig()
}

func initializeConfig() *config {
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
		newConfig.sleepTime = *sleepTime
		kubernetesMonitor := os.Getenv("KUBERNETESMONITOR")
		kubernetesRemove := os.Getenv("KUBERNETESREMOVE")
		kubernetesDoRollout := os.Getenv("KUBERNETES_ROLLOUT")
		awsWriteback := os.Getenv("AWS_WRITEBACK")

		if kubernetesMonitor == "true" || kubernetesRemove == "true" {
			newConfig.Clientset = NewKubernetesClient()
		}
		if awsWriteback == "true" {
			newConfig.awsAccessKeyId = os.Getenv("AWS_ACCESS_KEY_ID")
			newConfig.awsSecretAccessKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
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
		return &newConfig
	}
	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
func startRaven(RavenCfg *config) {
	if RavenCfg != nil {
		log.WithFields(log.Fields{"config": newConfig}).Debug("Setting newConfig variables. preparing to run. ")
		client, err := client()
		if err != nil {
			log.WithFields(log.Fields{"config": newConfig}).Fatal("failed to initialize client")

		}

		if validToken(client) {
			// start webserver
			go handleRequests(newConfig)
			// ensure paths for first time.
			newpath := filepath.Join(RavenCfg.clonePath, RavenCfg.secretEngine)
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
						// ..and push new files if there were any. If there are any ripe secrets, delete.
						PickedRipeSecrets := PickRipeSecrets(State, mySecretList)
						HarvestRipeSecrets(PickedRipeSecrets, newConfig)
						gitPush(newConfig)
						log.WithFields(log.Fields{"PickedRipeSecrets": PickedRipeSecrets}).Debug("PickedRipeSecrets list")
						State = mySecretList
						sleep(RavenCfg.sleepTime)
					}
				}
			}
		} else {
			log.WithFields(log.Fields{"token": RavenCfg.token}).Warn("Token is invalid, need to update. ")
			WriteErrorToTerminationLog("[*] token is invalid, someone needs to update this![*]")
		}
	}
}
