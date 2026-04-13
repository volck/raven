package main

import (
	"fmt"
	"testing"
)

func Test_persistVaultChangesMySecretListEmpty(t *testing.T) {

	t.Parallel()

	cluster := createVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client
	config := config{
		vaultEndpoint: cluster.Cores[0].Client.Address(),
		secretEngine:  "kv",
		token:         client.Token(),
		destEnv:       "kv",
		pemFile:       "cert.crt",
	}
	// we make no secrets, so that list is empty
	list, err := getAllKVs(client, config)
	if err != nil {
		fmt.Println(err)
	}
	if list != nil {
		secretList := list.Data["keys"].([]interface{})
		synchronizeVaultSecrets(secretList, client, config)
	} else {
		fmt.Println("list is empty. ")
	}
}