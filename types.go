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
	Clientset         kubernetes.Interface
}

var secretNameLog []string

type SecretContents struct {
	stringdata  map[string]string
	data        map[string][]byte
	Annotations map[string]string
	name        string
	Labels      map[string]string
}
