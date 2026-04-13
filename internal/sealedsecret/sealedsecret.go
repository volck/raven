package sealedsecret

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"

	sealedSecretPkg "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
	"github.com/hashicorp/vault/api"
	"github.com/volck/raven/internal/helpers"
	vaultpkg "github.com/volck/raven/internal/vault"
	"gopkg.in/yaml.v2"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	k8sJson "k8s.io/apimachinery/pkg/runtime/serializer/json"
)

var jsonLogger = helpers.JsonLogger

func ReadSealedSecretAndCompareWithVaultStruct(secret string, kv *api.Secret, filepointer string, secretEngine string) (NeedUpdate bool) {
	NeedUpdate = false
	VaultTimeStamp := kv.Data["metadata"].(map[string]interface{})["created_time"]
	theArnFromVault, err := vaultpkg.ExtractCustomKeyFromCustomMetadata("AWS_ARN_REF", kv)
	if err != nil {
		jsonLogger.Debug("readSealedSecretAndCompareWithVaultStruct.ExtractCustomKeyFromCustomMetadata", "error", err)
	}

	data, err := os.ReadFile(filepointer)
	if err != nil {
		jsonLogger.Info("readSealedSecretAndCompareWithVaultStruct.ReadFile Marking for update", slog.Any("error", err), slog.Any("filepointer", filepointer))
		return true
	}

	v := make(map[string]interface{})
	err = yaml.Unmarshal(data, &v)
	if err != nil {
		jsonLogger.Info("readSealedSecretAndCompareWithVaultStruct.YAML.Unmarshal error. Marking for update", slog.Any("error", err))
		return true
	}

	if _, ok := v["metadata"]; ok {
		if !ok {
			jsonLogger.Info("readSealedSecretAndCompareWithVaultStruct: we need a update here", slog.Any("ok-status", ok), slog.String("action", "update"))
			NeedUpdate = true
		}
		SealedSecretTime := v["metadata"].(map[interface{}]interface{})["annotations"].(map[interface{}]interface{})["created_time"]
		SealedSecretARNRef := v["metadata"].(map[interface{}]interface{})["annotations"].(map[interface{}]interface{})["AWS_ARN_REF"]

		if SealedSecretARNRef != theArnFromVault {
			jsonLogger.Info("readSealedSecretAndCompareWithVaultStruct: ARN changed, need update", slog.String("action", "update"))
			NeedUpdate = true
		}
		SealedSecretSource := v["metadata"].(map[interface{}]interface{})["annotations"].(map[interface{}]interface{})["source"]
		if (VaultTimeStamp == SealedSecretTime) || (SealedSecretSource != secretEngine) {
			jsonLogger.Debug("readSealedSecretAndCompareWithVaultStruct match or different engine")
			return
		} else {
			NeedUpdate = true
			jsonLogger.Info("readSealedSecretAndCompareWithVaultStruct needUpdate", slog.String("action", "update"))
		}
	}
	return
}

func CreateSealedSecret(publickeyPath string, k8ssecret *v1.Secret) *sealedSecretPkg.SealedSecret {
	read, err := os.ReadFile(publickeyPath)
	if err != nil {
		jsonLogger.Error("createSealedSecret: Cannot read publickeyPath", slog.Any("error", err), slog.String("publickeyPath", publickeyPath))
		helpers.WriteErrorToTerminationLog("Cannot read publickeyPath: " + err.Error())
	}
	block, _ := pem.Decode(read)
	if block == nil {
		jsonLogger.Error("createSealedSecret: failed to parse PEM block", "pemDecode", publickeyPath)
		helpers.WriteErrorToTerminationLog("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		jsonLogger.Error("createSealedSecret: failed to parse DER encoded public key", "error", err)
		helpers.WriteErrorToTerminationLog("failed to parse DER encoded public key: " + err.Error())
	}

	var codecs serializer.CodecFactory
	rsaPublicKey, _ := pub.PublicKey.(*rsa.PublicKey)
	sealedSecret, err := sealedSecretPkg.NewSealedSecret(codecs, rsaPublicKey, k8ssecret)
	if err != nil {
		jsonLogger.Error("createSealedSecret.NewSealedSecret", "error", err)
		helpers.WriteErrorToTerminationLog("failed to create sealed secret: " + err.Error())
	}

	sealedSecret.TypeMeta = k8ssecret.TypeMeta
	sealedSecret.ObjectMeta = k8ssecret.ObjectMeta
	return sealedSecret
}

func SerializeSealedSecretToFile(SealedSecret *sealedSecretPkg.SealedSecret, fullPath string) {
	f, err := os.Create(fullPath)
	if err != nil {
		jsonLogger.Error("SerializeSealedSecretToFile.Os.Create", "error", err)
		helpers.WriteErrorToTerminationLog(err.Error())
	}

	options := k8sJson.SerializerOptions{
		Yaml:   true,
		Pretty: true,
		Strict: true,
	}
	e := k8sJson.NewSerializerWithOptions(k8sJson.DefaultMetaFactory, nil, nil, options)
	err = e.Encode(SealedSecret, f)
	if err != nil {
		jsonLogger.Error("SerializeSealedSecretToFile encoding error", "error", err)
		helpers.WriteErrorToTerminationLog(err.Error())
	}
}
