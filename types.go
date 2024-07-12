package main

import (
	"github.com/hashicorp/vault/api"
	"k8s.io/client-go/kubernetes"
)

type config struct {
	vaultEndpoint      string
	secretEngine       string
	token              string
	destEnv            string
	pemFile            string
	clonePath          string
	repoUrl            string
	DocumentationKeys  []string
	Clientset          kubernetes.Interface
	awsRegion          string
	awsAccessKeyId     string
	awsSecretAccessKey string
	sleepTime          int
}

var secretNameLog []string

var mySecretList = map[string]*api.Secret{}

type SecretContents struct {
	stringdata  map[string]string
	data        map[string][]byte
	Annotations map[string]string
	name        string
	Labels      map[string]string
}

var added = make(chan string)
