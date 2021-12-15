package main

import (
	"fmt"
	"github.com/go-git/go-git/v5"
	"net/http"
	"path/filepath"
	"strings"

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
	k8sSecret := createK8sSecret(secretName, config, SingleKVFromVault)
	log.WithFields(log.Fields{"k8sSecret": k8sSecret}).Debug("getKVAndCreateSealedSecret.k8sSecret")
	SealedSecret = createSealedSecret(config.pemFile, &k8sSecret)
	log.WithFields(log.Fields{"SealedSecret": SealedSecret}).Debug("getKVAndCreateSealedSecret.SealedSecret")
	return
}

func PickRipeSecrets(PreviousKV []interface{}, NewKV []interface{}) (RipeSecrets []string) {
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

// take a starting path and return all KVs below it
func traverseVaultAndGetKVs(client *api.Client, config config, subdir string) (Secrets []interface{}, err error) {
	url := fmt.Sprintf("%s/metadata%s", config.secretEngine, subdir)
	list, err := client.Logical().List(url)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("getAllKVs list error")
	}
	secretList := list.Data["keys"].([]interface{})
	for _, secret := range secretList {
		if strings.HasSuffix(secret.(string), "/") {
			subdirList, _ := traverseVaultAndGetKVs(client, config, filepath.Join("/", secret.(string)))
			Secrets = mergeSecretLists(Secrets, subdirList)
		} else {
			sub := filepath.Join(subdir, secret.(string))
			Secrets = append(Secrets, sub)
		}
	}
	return Secrets, err
}

func mergeSecretLists(list1 []interface{}, list2 []interface{}) []interface{} {
	result := make([]interface{}, 0, len(list1)+len(list2))
	for i := range list1 {
		result = append(result, list1[i])
	}
	for i := range list2 {
		result = append(result, list2[i])
	}
	return result
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
