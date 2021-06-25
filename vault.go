package main

import (
	"fmt"
	"net/http"

	"reflect"

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
func getKVAndCreateSealedSecret(secretEngine string, secretName string, token string, destEnv string, pemFile string) (SealedSecret *sealedSecretPkg.SealedSecret, SingleKVFromVault *api.Secret) {
	SingleKVFromVault = getSingleKV(secretEngine, secretName)
	log.WithFields(log.Fields{"SingleKVFromVault": SingleKVFromVault}).Debug("getKVAndCreateSealedSecret.SingleKVFromVault")
	k8sSecret := createK8sSecret(secretName, destEnv, secretEngine, SingleKVFromVault)
	log.WithFields(log.Fields{"k8sSecret": k8sSecret}).Debug("getKVAndCreateSealedSecret.k8sSecret")
	SealedSecret = createSealedSecret(pemFile, &k8sSecret)
	log.WithFields(log.Fields{"SealedSecret": SealedSecret}).Debug("getKVAndCreateSealedSecret.SealedSecret")
	return
}

/*
PickRipeSecrets() uses Alive() to check if we have dead secrets

*/

func PickRipeSecrets(PreviousKV *api.Secret, NewKV *api.Secret) (RipeSecrets []string) {
	log.WithFields(log.Fields{
		"previousKeys": PreviousKV.Data["keys"],
		"newKV":        NewKV.Data["keys"],
	}).Debug("PickRipeSecrets is starting to compare lists")

	if PreviousKV.Data["keys"] == nil || NewKV.Data["keys"] == nil {
		// we assume this is our first run so we do not know difference yet.
		log.WithFields(log.Fields{
			"previousKeys": PreviousKV.Data["keys"],
			"newKV":        NewKV.Data["keys"],
		}).Debug("PickRipeSecrets compared lists and found that either of the lists were nil")

	} else if reflect.DeepEqual(PreviousKV.Data["keys"], NewKV.Data["keys"]) {
		log.WithFields(log.Fields{
			"previousKeys": PreviousKV.Data["keys"],
			"newKV":        NewKV.Data["keys"],
		}).Debug("PickRipeSecrets: Lists match.")
	} else {
		for _, v := range PreviousKV.Data["keys"].([]interface{}) {
			isAlive := Alive(NewKV.Data["keys"].([]interface{}), v.(string))
			if !isAlive {
				log.WithFields(log.Fields{"PreviousKV.Data": PreviousKV.Data}).Debug("PickRipeSecrets: We have found a ripe secret. adding it to list of ripesecrets now.")
				log.WithFields(log.Fields{"RipeSecret": v.(string)}).Info("PickRipeSecrets: We have found a ripe secret. adding it to list of ripesecrets now.")
				RipeSecrets = append(RipeSecrets, v.(string))
				log.WithFields(log.Fields{"RipeSecret": RipeSecrets}).Debug("PickRipeSecrets final list of ripe secrets")
			}
		}
	}
	return
}

/*
getallKvs parameters:
enviroment(i.e qa??, dev??)
*/

func getAllKVs(env string, token string) (Secret *api.Secret, err error) {

	client, err := client()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("getAllKVs client error")
	}
	url := env + "/metadata"

	Secret, err = client.Logical().List(url)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("getAllKVs list error")
	}
	return Secret, err
}

/*
getsingleKV() used to iterate struct from getAllKVs(), takes secretname as input, returns struct for single secret. Requires uniform data.
*/

func getSingleKV(env string, secretname string) (Secret *api.Secret) {
	//url := vaultEndPoint + "/v1/" + env + "/data/" + secretname
	client, err := client()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("getSingleKV client error")
	}
	path := fmt.Sprintf("%s/data/%s", env, secretname)

	Secret, err = client.Logical().Read(path)
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

/* validateSelftoken() takes token as input,
returns false if tokens has errors or is invalid.
*/

func validateSelftoken(vaultEndPoint string, token string) (valid bool) {

	client, err := client()
	if err != nil {
		fmt.Printf("client.ValidateSelfToken() failed: %s \n ", err)
	}

	_, err = client.Auth().Token().LookupSelf()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("validateSelfTokenlookupself failed")
		valid = false
		return valid
	}
	valid = true
	return valid

}
