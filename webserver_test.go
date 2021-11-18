package main

import (
	"fmt"
	"testing"
)

func TestForceNewSecrets(t *testing.T) {

	cluster := createVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client
	config := config{
		vaultEndpoint: cluster.Cores[0].Client.Address(),
		secretEngine:  "kv",
		token:         client.Token(),
		destEnv:       "kv",
		pemFile: 	`\\p0home001\UnixHome\a01631\dev\raven\ntcert.crt`,
	}
	secretName := "secret"
	secretNameTwo := "secrettwo"
	generateTestSecrets(t, client, config, secretName)
	generateTestSecrets(t, client, config, secretNameTwo)
	list, err := getAllKVs(client, config)
	if err != nil {
		fmt.Println("getkvlist err", err)
	}
	fmt.Println(list)
	forcenewSecrets(client,config)
}

func TestForceNewSecretsWithEmptyKV(t *testing.T) {

	cluster := createVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client
	config := config{
		vaultEndpoint: cluster.Cores[0].Client.Address(),
		secretEngine:  "kv",
		token:         client.Token(),
		destEnv:       "kv",
		pemFile: 	`cert.crt`,
	}
	list, err := getAllKVs(client, config)
	if err != nil {
		fmt.Println("getkvlist err", err)
	}
	fmt.Println(list)
	forcenewSecrets(client,config)
}

