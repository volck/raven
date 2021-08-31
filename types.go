package main

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

type SecretContents struct {
	stringdata map[string]string
	data map[string][]byte
	Annotations map[string]string
	name string
}
