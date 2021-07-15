package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	sealedSecretPkg "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"reflect"
)

/*
	readSealedSecretAndCompareWithVaultStruct takes a vault KV as parameter as well as a filepointer pointing to a local yaml file.

*/

func readSealedSecretAndCompareWithVaultStruct(secret string, kv *api.Secret, filepointer string, secretEngine string) (NeedUpdate bool) {
	NeedUpdate = false
	VaultTimeStamp := kv.Data["metadata"].(map[string]interface{})["created_time"]

	//grab SealedSecret file
	data, err := ioutil.ReadFile(filepointer)
	if err != nil {
		WriteErrorToTerminationLog(err.Error())
		log.WithFields(log.Fields{"filepointer": filepointer, "error": err.Error()}).Error("readSealedSecretAndCompareWithVaultStruct.ioutil.ReadFile")

	}
	//unmarshal it into a interface
	v := make(map[string]interface{})
	err = yaml.Unmarshal(data, &v)
	if err != nil {
		WriteErrorToTerminationLog(err.Error())
		log.WithFields(log.Fields{"data": data, "v": v, "error": err.Error()}).Fatal("readSealedSecretAndCompareWithVaultStruct.YAML.Unmarshal")
	}
	// hacky way of getting variable
	if _, ok := v["metadata"]; ok {
		if !ok {
			log.WithFields(log.Fields{"ok-status": ok}).Info("readSealedSecretAndCompareWithVaultStruct: we need a update here")
			NeedUpdate = true
		}
		SealedSecretTime := v["metadata"].(map[interface{}]interface{})["annotations"].(map[interface{}]interface{})["created_time"]
		SealedSecretSource := v["metadata"].(map[interface{}]interface{})["annotations"].(map[interface{}]interface{})["source"]
		if VaultTimeStamp == SealedSecretTime || SealedSecretSource != secretEngine {
			log.WithFields(log.Fields{"VaultTimeStamp": VaultTimeStamp, "SealedSecretTime": SealedSecretTime, "SealedSecretSource": SealedSecretSource, "secretEngine": secretEngine, "NeedUpdate": NeedUpdate}).Debug("readSealedSecretAndCompareWithVaultStruct either we have a match here, or secret is from another secretengine")
			return
		} else {
			NeedUpdate = true
			log.WithFields(log.Fields{"secret": secret, "vaultTimestamp": VaultTimeStamp, "SealedSecretTime": SealedSecretTime, "NeedUpdate": NeedUpdate}).Info("readSealedSecretAndCompareWithVaultStruct needUpdate")
		}
	}
	return
}

/*
createSealedSecret takes two arguments:
publicKeyPath: path to PEM file.
k8ssecret: kubernetes secret generated from createK8sSecret when iterating list of secrets.

*/
func createSealedSecret(publickeyPath string, k8ssecret *v1.Secret) (sealedSecret *sealedSecretPkg.SealedSecret) {
	read, err := ioutil.ReadFile(publickeyPath)
	if err != nil {
		log.WithFields(log.Fields{"publickeyPath": publickeyPath, "error": err}).Fatal("createSealedSecret.ioutil.ReadFile: Cannot read publickeyPath")
	}
	block, _ := pem.Decode([]byte(read))
	if block == nil {
		log.WithFields(log.Fields{
			"pemDecode": publickeyPath,
		}).Fatal("createSealedSecret.Pem.Decode() failed to parse PEM block containing the public key")
		WriteErrorToTerminationLog("failed to parse PEM block containing the public key")
	}
	var pub *x509.Certificate

	pub, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.WithFields(log.Fields{"block.Bytes": block.Bytes, "error": err.Error()}).Fatal("createSealedSecret.Pem.Decode() failed to parse DER encoded public key: ")
		WriteErrorToTerminationLog("failed to parse DER encoded public key: " + err.Error())
	}
	var codecs serializer.CodecFactory
	rsaPublicKey, _ := pub.PublicKey.(*rsa.PublicKey)
	sealedSecret, err = sealedSecretPkg.NewSealedSecret(codecs, rsaPublicKey, k8ssecret)
	if err != nil {
		log.WithFields(log.Fields{"sealedSecret": sealedSecret, "error": err.Error()}).Error("createSealedSecret.sealedSecretPkg.NewSealedSecret")
		WriteErrorToTerminationLog("failed to parse DER encoded public key: " + err.Error())
	}
	// apparently we need to specifically assign these fields.
	sealedSecret.TypeMeta = k8ssecret.TypeMeta
	sealedSecret.ObjectMeta = k8ssecret.ObjectMeta
	return
}

func firstRun(PreviousKV *api.Secret, NewKV *api.Secret) bool {
	validator := false
	if PreviousKV.Data["keys"] == nil || NewKV.Data["keys"] == nil {
		log.WithFields(log.Fields{"previousKeys": PreviousKV.Data["keys"], "newKV": NewKV.Data["keys"]}).Debug("PickRipeSecrets compared lists and found that either of the lists were nil")
		validator = true
	}
	return validator
}

func listsEmpty(PreviousKV *api.Secret, NewKV *api.Secret)(bool) {
	emptyList := false
	if NewKV == nil {
		emptyList = true
	}
	return emptyList
}


func listsMatch(PreviousKV *api.Secret, NewKV *api.Secret) bool {
	validator := false

	if reflect.DeepEqual(PreviousKV.Data["keys"], NewKV.Data["keys"]) {
		log.WithFields(log.Fields{"previousKeys": PreviousKV.Data["keys"], "newKV": NewKV.Data["keys"]}).Debug("PickRipeSecrets: Lists match.")
		validator = true
	}
	return validator
}

func findRipeSecrets(PreviousKV *api.Secret, NewKV *api.Secret) (RipeSecrets []string) {
	for _, v := range PreviousKV.Data["keys"].([]interface{}) {
		isAlive := Alive(NewKV.Data["keys"].([]interface{}), v.(string))
		if !isAlive {
			log.WithFields(log.Fields{"PreviousKV.Data": PreviousKV.Data}).Debug("PickRipeSecrets: We have found a ripe secret. adding it to list of ripesecrets now.")
			log.WithFields(log.Fields{"RipeSecret": v.(string)}).Info("PickRipeSecrets: We have found a ripe secret. adding it to list of ripesecrets now.")
			RipeSecrets = append(RipeSecrets, v.(string))
			log.WithFields(log.Fields{"RipeSecret": RipeSecrets}).Debug("PickRipeSecrets final list of ripe secrets")
		}
	}
	return RipeSecrets
}
