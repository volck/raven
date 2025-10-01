package main

import (
	"flag"
	"fmt"
	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log/slog"
	"os"
	"path/filepath"
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
	awsWriteBack := flag.Bool("awsWriteBack", getBoolEnv("AWS_WRITEBACK", false), "enable AWS writeback")

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
		kubernetesDelete := os.Getenv("KUBERNETESREMOVE")
		kubernetesDoRollout := os.Getenv("KUBERNETES_ROLLOUT")

		if kubernetesMonitor == "true" || kubernetesDelete == "true" {
			newConfig.Clientset = NewKubernetesClient()
		}
		if *awsWriteBack == true {
			newConfig.awsWriteback = true
			newConfig.awsAccessKeyId = os.Getenv("AWS_ACCESS_KEY_ID")
			newConfig.awsSecretAccessKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
			newConfig.awsRegion = os.Getenv("AWS_REGION")
			newConfig.awsSecretPrefix = os.Getenv("AWS_SECRET_PREFIX")
			newConfig.awsNotificationUrl = os.Getenv("AWS_NOTIFICATION_WEBHOOK_URL")
			newConfig.awsRole = os.Getenv("AWS_ROLE_NAME")
			jsonLogger.Info("AWS writeback enabled", "region", newConfig.awsRegion, "secretprefix", newConfig.awsSecretPrefix, "role", newConfig.awsRole)
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
	if RavenCfg == nil {
		return
	}

	jsonLogger.Debug("Setting newConfig variables", "config", newConfig)
	vaultClient, err := client()
	if err != nil {
		jsonLogger.Error("Failed to initialize vaultClient", "config", newConfig)
		WriteErrorToTerminationLog("Failed to initialize vaultClient")
	}

	if !validToken(vaultClient) {
		jsonLogger.Warn("Token is invalid, need to update", "token", RavenCfg.token)
		WriteErrorToTerminationLog("[*] token is invalid, someone needs to update this![*]")
		return
	}

	go handleRequests(newConfig)
	newpath := filepath.Join(RavenCfg.clonePath, RavenCfg.secretEngine)
	if err := os.MkdirAll(newpath, os.ModePerm); err != nil {
		jsonLogger.Error("Failed to ensure paths for first time", "NewPath", newpath)
		WriteErrorToTerminationLog("os.Mkdir failed when trying to ensure paths for first time")
	}

	GitClone(newConfig)
	State := map[string]*api.Secret{}

	for {
		if !validToken(vaultClient) {
			continue
		}
		jsonLogger.Debug("Validated Token: grabbing list of secrets")
		list, err := getAllKVs(vaultClient, newConfig)
		if err != nil {
			jsonLogger.Error("getAllKVs list error", "error", err)
			continue
		}

		if list == nil {
			cleanDeadEntries()
			continue
		}

		currentSecrets = map[string]*api.Secret{}
		secretList := list.Data["keys"].([]interface{})
		synchronizeVaultSecrets(secretList, vaultClient, newConfig)
		PickedRipeSecrets := PickRipeSecrets(State, currentSecrets)
		ripeAwsSecrets := findRipeAWSSecrets(State, currentSecrets)
		WriteMissingAWSSecrets(currentSecrets, newConfig)
		HarvestRipeSecrets(PickedRipeSecrets, newConfig)
		HarvestRipeAwsSecrets(ripeAwsSecrets, newConfig)
		gitPush(newConfig)
		jsonLogger.Debug("PickedRipeSecrets list", "PickedRipeSecrets", PickedRipeSecrets, "ripeAwsSecrets", ripeAwsSecrets)

		State = currentSecrets
		sleep(RavenCfg.sleepTime)
	}
}
