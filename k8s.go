package main

import (
	"encoding/base64"
	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"reflect"
	"strconv"
	"strings"
)

func applyAnnotations(dataFields *api.Secret, config config) map[string]string {

	Annotations := make(map[string]string)
	Annotations["source"] = config.secretEngine

	if len(dataFields.Data) == 0 {
		log.WithFields(log.Fields{`len(data["metadata"])`: len(dataFields.Data)}).Debug("No datafields placed")
	} else {
		for k, v := range dataFields.Data["metadata"].(map[string]interface{}) {
			switch v.(type) {
			case float64:
				float64value := reflect.ValueOf(v)
				float64convert := strconv.FormatFloat(float64value.Float(), 'f', -1, 64)
				Annotations[k] = float64convert
			case string:
				Annotations[k] = v.(string)
			case bool:
				booleanvalue := reflect.ValueOf(v)
				boolconvert := strconv.FormatBool(booleanvalue.Bool())
				Annotations[k] = boolconvert
			}
		}
	}

	return Annotations
}

func applyDatafieldsTok8sSecret(dataFields *api.Secret, config config, Annotations map[string]string) (data map[string][]byte, stringdata map[string]string) {
	stringdata = make(map[string]string)

	data = make(map[string][]byte)
	if len(dataFields.Data["data"].(map[string]interface{})) == 0 {
		log.WithFields(log.Fields{`len(data["metadata"])`: len(dataFields.Data["metadata"].(map[string]interface{}))}).Debug("No datafields placed")
		return data, stringdata
	}
	for k, v := range dataFields.Data["data"].(map[string]interface{}) {
		log.WithFields(log.Fields{"key": k, "value": v, "datafields": dataFields.Data["data"]}).Debug("createK8sSecret: dataFields.Data[data] iterate")
		if strings.HasPrefix(v.(string), "base64:") {
			stringSplit := strings.Split(v.(string), ":")
			if isBase64(stringSplit[1]) {
				data[k], _ = base64.StdEncoding.DecodeString(stringSplit[1])

				log.WithFields(log.Fields{"key": k, "value": v, "split": stringSplit, "datafields": dataFields.Data["data"]}).Debug("createK8sSecret: dataFields.Data[data] found base64-encoding")
			} else {
				log.WithFields(log.Fields{"key": k, "value": v}).Warn("key is not valid BASE64")
			}
		} else if isDocumentationKey(newConfig.DocumentationKeys, k) {
			Annotations[k] = v.(string)
			log.WithFields(log.Fields{"key": k, "value": v, "datafields": dataFields.Data["data"], "Annotations": Annotations}).Debug("createK8sSecret: dataFields.Data[data] found description field")
		} else {
			stringdata[k] = v.(string)
			log.WithFields(log.Fields{"key": k, "value": v, "datafields": dataFields.Data["data"]}).Debug("createK8sSecret: dataFields.Data[data] catch all. putting value in stringdata[]")
		}
	}
	return data, stringdata
}

func applyMetadata(dataFields *api.Secret, config config, Annotations map[string]string) map[string]string {

	if len(dataFields.Data["metadata"].(map[string]interface{})) == 0 {
		log.WithFields(log.Fields{`len(data["metadata"])`: len(dataFields.Data["metadata"].(map[string]interface{}))}).Debug("No metadata placed")
		return Annotations
	}
	for k, v := range dataFields.Data["metadata"].(map[string]interface{}) {
		// we handle descriptions for KVs here, in order to show which secrets are handled by which SSG.
		switch v.(type) {
		case float64:
			float64value := reflect.ValueOf(v)
			float64convert := strconv.FormatFloat(float64value.Float(), 'f', -1, 64)
			Annotations[k] = float64convert
			log.WithFields(log.Fields{"key": k, "value": v, "datafields": dataFields.Data["metadata"]}).Debug("createK8sSecret: dataFields.Data[metadata] case match float64 ")
		case string:
			Annotations[k] = v.(string)
			log.WithFields(log.Fields{"key": k, "value": v, "datafields": dataFields.Data["metadata"]}).Debug("createK8sSecret: dataFields.Data[metadata] case match string ")
		case bool:
			booleanvalue := reflect.ValueOf(v)
			boolconvert := strconv.FormatBool(booleanvalue.Bool())
			Annotations[k] = boolconvert
			log.WithFields(log.Fields{"key": k, "value": v, "datafields": dataFields.Data["metadata"]}).Debug("createK8sSecret: dataFields.Data[metadata] case match bool ")
		}

	}
	return Annotations

}

func NewSecretWithContents(contents SecretContents, config config) (secret v1.Secret) {
	secret = v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SealedSecret",
			APIVersion: "bitnami.com/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        contents.name,
			Namespace:   config.destEnv,
			Annotations: contents.Annotations,
		},
		Data:       contents.data,
		StringData: contents.stringdata,
		Type:       "Opaque",
	}
	return secret
}
