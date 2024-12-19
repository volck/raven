package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"

	"reflect"

	sealedSecretPkg "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
	"github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v2"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

/*
	readSealedSecretAndCompareWithVaultStruct takes a vault KV as parameter as well as a filepointer pointing to a local yaml file.

*/

func readSealedSecretAndCompareWithVaultStruct(secret string, kv *api.Secret, filepointer string, secretEngine string) (NeedUpdate bool) {
	NeedUpdate = false
	VaultTimeStamp := kv.Data["metadata"].(map[string]interface{})["created_time"]
	theArnFromVault, err := ExtractCustomKeyFromCustomMetadata("AWS_ARN_REF", kv)
	if err != nil {
		jsonLogger.Error("readSealedSecretAndCompareWithVaultStruct.ExtractCustomKeyFromCustomMetadata", "error", err)
	}
	//grab SealedSecret file
	data, err := os.ReadFile(filepointer)
	if err != nil {
		jsonLogger.Info("readSealedSecretAndCompareWithVaultStruct.ioutil.ReadFile Marking for update", slog.Any("error", err), slog.Any("filepointer", filepointer))
		return true
		//WriteErrorToTerminationLog(err.Error())
	}
	//unmarshal it into a interface
	v := make(map[string]interface{})
	err = yaml.Unmarshal(data, &v)
	if err != nil {
		jsonLogger.Info("readSealedSecretAndCompareWithVaultStruct.YAML.Unmarshal error. Marking for update", slog.Any("error", err), slog.Any("data", data), slog.Any("v", v))
		return true
	}
	// hacky way of getting variable
	if _, ok := v["metadata"]; ok {
		if !ok {
			jsonLogger.Info("readSealedSecretAndCompareWithVaultStruct: we need a update here", slog.Any("ok-status", ok), slog.String("action", "update"))
			NeedUpdate = true
		}
		SealedSecretTime := v["metadata"].(map[interface{}]interface{})["annotations"].(map[interface{}]interface{})["created_time"]
		SealedSecretARNRef := v["metadata"].(map[interface{}]interface{})["annotations"].(map[interface{}]interface{})["AWS_ARN_REF"]

		if SealedSecretARNRef != theArnFromVault {
			jsonLogger.Info("readSealedSecretAndCompareWithVaultStruct: we need a update here", slog.String("action", "update"), slog.Any("SealedSecretARNRef", SealedSecretARNRef), slog.Any("theArnFromVault", theArnFromVault))
			NeedUpdate = true
		}
		SealedSecretSource := v["metadata"].(map[interface{}]interface{})["annotations"].(map[interface{}]interface{})["source"]
		if (VaultTimeStamp == SealedSecretTime) || (SealedSecretSource != secretEngine) {
			jsonLogger.Debug("readSealedSecretAndCompareWithVaultStruct either we have a match here, or secret is from another secretengine", slog.Any("VaultTimeStamp", VaultTimeStamp), slog.Any("SealedSecretTime", SealedSecretTime), slog.Any("SealedSecretSource", SealedSecretSource), slog.String("action", "update"))
			return
		} else {
			NeedUpdate = true
			jsonLogger.Info("readSealedSecretAndCompareWithVaultStruct needUpdate", slog.String("action", "update"), slog.Any("VaultTimeStamp", VaultTimeStamp), slog.Any("SealedSecretTime", SealedSecretTime))
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
	read, err := os.ReadFile(publickeyPath)
	if err != nil {
		jsonLogger.Error("createSealedSecret.ioutil.ReadFile: Cannot read publickeyPath", slog.Any("error", err), slog.String("publickeyPath", publickeyPath))
		WriteErrorToTerminationLog("Cannot read publickeyPath: " + err.Error())
	}
	block, _ := pem.Decode(read)
	if block == nil {
		jsonLogger.Error("createSealedSecret.Pem.Decode() failed to parse PEM block containing the public key",
			"pemDecode", publickeyPath)
		WriteErrorToTerminationLog("failed to parse PEM block containing the public key")
	}
	var pub *x509.Certificate

	pub, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		jsonLogger.Error("createSealedSecret.Pem.Decode() failed to parse DER encoded public key", "error", err, "block.Bytes", block.Bytes)
		WriteErrorToTerminationLog("failed to parse DER encoded public key: " + err.Error())
	}
	var codecs serializer.CodecFactory
	rsaPublicKey, _ := pub.PublicKey.(*rsa.PublicKey)
	sealedSecret, err = sealedSecretPkg.NewSealedSecret(codecs, rsaPublicKey, k8ssecret)
	if err != nil {
		jsonLogger.Error("createSealedSecret.sealedSecretPkg.NewSealedSecret", "error", err, slog.Any("sealedSecret", sealedSecret))
		WriteErrorToTerminationLog("failed to parse DER encoded public key: " + err.Error())
	}
	// apparently we need to specifically assign these fields.
	sealedSecret.TypeMeta = k8ssecret.TypeMeta
	sealedSecret.ObjectMeta = k8ssecret.ObjectMeta
	return
}

func firstRun(PreviousKV map[string]*api.Secret, NewKV map[string]*api.Secret) bool {
	validator := false
	if PreviousKV == nil || NewKV == nil {
		jsonLogger.Debug("PickRipeSecrets compared lists and found that either of the lists were nil", slog.Any("previousKeys", PreviousKV), slog.Any("newKV", NewKV))
		validator = true
	}
	return validator
}

func listsEmpty(PreviousKV map[string]*api.Secret, NewKV map[string]*api.Secret) bool {
	emptyList := false
	if NewKV == nil || PreviousKV == nil {
		emptyList = true
	}
	return emptyList
}

func listsMatch(PreviousKV map[string]*api.Secret, NewKV map[string]*api.Secret) bool {
	validator := false
	if reflect.DeepEqual(PreviousKV, NewKV) {
		jsonLogger.Debug("PickRipeSecrets: Lists match.", "previousKeys", PreviousKV, "newKV", NewKV)
		validator = true
	}
	return validator
}

func findRipeSecrets(PreviousKV map[string]*api.Secret, NewKV map[string]*api.Secret) (RipeSecrets []string) {
	for k, _ := range PreviousKV {
		//		containsString := SliceContainsString(NewKV.Data["keys"].([]interface{}), v.(string))
		containsString := KeyInDictionary(NewKV, k)
		if !containsString {
			jsonLogger.Info("PickRipeSecrets: We have found a ripe secret. adding it to list of ripesecrets now.", "RipeSecret", k, "action", "delete")
			RipeSecrets = append(RipeSecrets, k)
			jsonLogger.Debug("PickRipeSecrets final list of ripe secrets", "RipeSecret", RipeSecrets)
			RipeSecrets = append(RipeSecrets, k)
		}
	}
	return RipeSecrets
}
