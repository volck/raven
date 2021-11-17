package main

import "k8s.io/client-go/kubernetes"

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

type vaultConfig struct {
	vaultEndpoint string
	secretEngine  string
	token         string
}

type gitConfig struct {
	clonePath string
	repoUrl   string
}

var secretNameLog []string
var Clientset *kubernetes.Clientset


type SecretContents struct {
	stringdata  map[string]string
	data        map[string][]byte
	Annotations map[string]string
	name        string
	Labels      map[string]string
}
