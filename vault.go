package main

import (
	"fmt"
	sealedSecretPkg "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
	"github.com/go-git/go-git/v5"
	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
	"net/http"
	"path/filepath"
	"strings"
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

func getKVAndCreateSealedSecret(client *api.Client, config config, secretName string) (sealedSecret *sealedSecretPkg.SealedSecret, SingleKVFromVault *api.Secret) {
	input := fmt.Sprintf("%s/", config.secretEngine)
	iterateList(input, client, secretName)

	for path, val := range mySecretList {
		log.WithFields(log.Fields{"SingleKVFromVault": val}).Debug("getKVAndCreateSealedSecret.SingleKVFromVault")
		k8sSecret := createK8sSecret(path, config, val)
		createSealedSecret(config.pemFile, &k8sSecret)
	}

	return
}

func PickRipeSecrets(PreviousKV map[string]*api.Secret, NewKV map[string]*api.Secret) (RipeSecrets []string) {
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

// env string, token string
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

func iterateList(input string, c *api.Client, secretName string) *api.Secret {
	p := ""
	if !strings.HasSuffix(input, "/") {
		p := strings.Replace(input, "/", "/data/", 1)
		Secret, err := c.Logical().Read(p)
		if err != nil {
			//fmt.Println("list data nil and we try to return a secret", err)
		}

		secretNameList := strings.Split(p, "/")
		pName := secretNameList[len(secretNameList)-1]
		mySecretList[pName] = Secret
		return Secret
	}

	//fmt.Println("first replacement of metadata", input, p)
	p = strings.Replace(input, "/", "/metadata/", 1)

	list, err := c.Logical().List(p) // kv/subpathone/metadata == kv/metadata/subpathone/
	if err != nil {
		//fmt.Println("list failed", err, list)
		return nil
	}
	if list.Data == nil {
		return nil
	}

	p = ""

	for _, k := range list.Data["keys"].([]interface{}) {
		p := strings.Replace(input, "/", "/metadata/", 1)
		if strings.HasSuffix(p, "/") {
			p = input + k.(string)
		} else {
			p = p + "/" + k.(string)
		}
		iterateList(p, c, "")
	}

	return nil
}

func getSingleKV(client *api.Client, env string, secretname string) (Secret *api.Secret) {
	//url := vaultEndPoint + "/v1/" + env + "/data/" + secretname
	path := fmt.Sprintf("%s/data/%s", env, secretname)
	Secret, err := client.Logical().Read(path)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("getSingleKV client read error")
	}
	return Secret

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

func GetCustomMetadataFromSecret(secret *api.Secret) (CustomMetadata map[string]interface{}, found bool) {

	if secret == nil {
		fmt.Println("secret is nil")
		return nil, false
	}

	metadata, ok := secret.Data["metadata"].(map[string]interface{})
	if !ok {
		fmt.Println("metadata is nil. returning")
		return nil, false
	}

	customMetadata, ok := metadata["custom_metadata"].(map[string]interface{})
	if !ok {
		return nil, false
	}
	return customMetadata, true
}
