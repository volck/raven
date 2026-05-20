package config

import (
	"k8s.io/client-go/kubernetes"
)

type Config struct {
	VaultEndpoint      string
	SecretEngine       string
	Token              string
	DestEnv            string
	PemFile            string
	ClonePath          string
	RepoUrl            string
	DocumentationKeys  []string
	Clientset          kubernetes.Interface
	AwsRegion          string
	AwsAccessKeyId     string
	AwsSecretAccessKey string
	SleepTime          int
	AwsSecretPrefix    string
	AwsNotificationUrl string
	AwsRole            string
	AwsWriteback       bool
}

type SecretContents struct {
	StringData  map[string]string
	Data        map[string][]byte
	Annotations map[string]string
	Name        string
	Labels      map[string]string
}
