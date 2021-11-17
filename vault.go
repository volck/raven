package main

import (
	"fmt"
	"github.com/go-git/go-git/v5"
	"net/http"
	"path/filepath"

	sealedSecretPkg "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
)

// We need to init the client a lot so this is a helper function which returns a fresh client.
func client() (*api.Client, error) {
	config := &api.Config{
		Address:    newConfig.vaultEndpoint,
		HttpClient: http.DefaultClient,
	}
	client, err := api.NewClient(config)
	if err != nil {
		log.WithFields(log.Fields{"config": config, "error": err.Error()}).Fatal("client.api.newclient() failed")
	}
	client.SetToken(newConfig.token)
	if err != nil {
		log.WithFields(log.Fields{"config": config, "error": err.Error()}).Fatal("client.api.SetToken() failed")
	}
	return client, err
}

/*
getKVAndCreateSealedSecret combines several "maker-methods":
* Get KV
* make k8ssecret
* return sealedsecretobject for further creation
* return KV object in order to compare later.

*/

func getKVAndCreateSealedSecret(client *api.Client, config config, secretName string) (SealedSecret *sealedSecretPkg.SealedSecret, SingleKVFromVault *api.Secret) {

	SingleKVFromVault = getSingleKV(client, config.secretEngine, secretName)
	log.WithFields(log.Fields{"SingleKVFromVault": SingleKVFromVault}).Debug("getKVAndCreateSealedSecret.SingleKVFromVault")
	k8sSecret := createK8sSecret(secretName, newConfig, SingleKVFromVault)
	log.WithFields(log.Fields{"k8sSecret": k8sSecret}).Debug("getKVAndCreateSealedSecret.k8sSecret")
	SealedSecret = createSealedSecret(newConfig.pemFile, &k8sSecret)
	log.WithFields(log.Fields{"SealedSecret": SealedSecret}).Debug("getKVAndCreateSealedSecret.SealedSecret")
	return
}

func PickRipeSecrets(PreviousKV *api.Secret, NewKV *api.Secret) (RipeSecrets []string) {
	if listsEmpty(PreviousKV, NewKV) {
	} else if !firstRun(PreviousKV, NewKV) && !listsMatch(PreviousKV, NewKV) {
		RipeSecrets = findRipeSecrets(PreviousKV, NewKV)
	}
	return RipeSecrets
}

func removeFromWorkingtree(RipeSecrets []string, worktree *git.Worktree, newConfig config) {
	for ripe := range RipeSecrets {
		base := filepath.Join("declarative", newConfig.destEnv, "sealedsecrets")
		newbase := base + "/" + RipeSecrets[ripe] + ".yaml"
		_, err := worktree.Remove(newbase)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Error("HarvestRipeSecrets worktree.Remove failed")
		}
		log.WithFields(log.Fields{"ripeSecret": RipeSecrets[ripe], "action": "delete"}).Info("HarvestRipeSecrets found ripe secret. marked for deletion")

	}
}

//env string, token string
func getAllKVs(client *api.Client, config config) (Secret *api.Secret, err error) {
	url := config.secretEngine + "/metadata"

	Secret, err = client.Logical().List(url)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("getAllKVs list error")
	}
	return Secret, err
}

/*
getsingleKV() used to iterate struct from getAllKVs(), takes secretname as input, returns struct for single secret. Requires uniform data.
*/

func getSingleKV(client *api.Client, env string, secretname string) (Secret *api.Secret) {
	//url := vaultEndPoint + "/v1/" + env + "/data/" + secretname

	path := fmt.Sprintf("%s/data/%s", env, secretname)

	Secret, err := client.Logical().Read(path)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("getSingleKV client read error")
	}
	return

}
func RenewSelfToken(token string, vaultEndpoint string) {
	client, err := client()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("RenewSelfToken client error")
	}
	clientToken, err := client.Auth().Token().RenewSelf(300) // renew for 5 more minutes.
	fmt.Println(clientToken)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("client.token.renewself() client error")
	}

}

func validToken(client *api.Client) (valid bool) {

	_, err := client.Auth().Token().LookupSelf()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("validateSelfTokenlookupself failed")
		valid = false
		return valid
	}
	valid = true
	return valid

}
