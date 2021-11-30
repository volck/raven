package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

func applyAnnotations(dataFields *api.Secret, config config) map[string]string {

	Annotations := make(map[string]string)
	Annotations["source"] = config.secretEngine
	if len(dataFields.Data["metadata"].(map[string]interface{})) == 0 {
		log.WithFields(log.Fields{`len(data["metadata"])`: len(dataFields.Data)}).Debug("No datafields applied")
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

func applyDatafieldsTok8sSecret(dataFields *api.Secret, Annotations map[string]string, name string) (data map[string][]byte, stringdata map[string]string) {
	stringdata = make(map[string]string)
	data = make(map[string][]byte)
	if dataFields.Data["data"] == nil {
		log.WithFields(log.Fields{"secret": name}).Info("Trying to apply data fields to kubernetes secret, but vault datafields seem to be empty. Was this secret deleted correctly? Skipping.")
	} else if len(dataFields.Data["data"].(map[string]interface{})) == 0 {
		log.WithFields(log.Fields{`len(data["metadata"])`: len(dataFields.Data["metadata"].(map[string]interface{})), "secret": name}).Info("Trying to apply datafields to kubernetes secret, but no datafields could be placed.")
		return data, stringdata
	} else {
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
	}
	return data, stringdata

}

func applyRavenLabels() map[string]string {
	labels := make(map[string]string)
	labels["managedBy"] = "raven"
	return labels
}

func applyMetadata(dataFields *api.Secret, Annotations map[string]string) map[string]string {

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
			Labels:      contents.Labels,
		},
		Data:       contents.data,
		StringData: contents.stringdata,
		Type:       "Opaque",
	}
	return secret
}

func initk8sServiceAccount() *kubernetes.Clientset {
	// creates the in-cluster config

	config, err := rest.InClusterConfig()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Info("initk8sServiceAccount incluster config failed")

	}
	// creates the clientset
	Clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Info("initk8sServiceAccount clientset failed")
	}
	return Clientset

}

func kubernetesSecretList(c kubernetes.Interface, destEnv string) (*v1.SecretList, error) {
	sl, err := c.CoreV1().Secrets(destEnv).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		fmt.Println("clientset secrets.err", err)
	}
	return sl, err
}

func hask8sRavenLabel(secret v1.Secret) bool {
	haslabel := false
	if secret.Labels["managedBy"] == "raven" {
		haslabel = true
	}

	return haslabel
}

func kubernetesRemove(ripeSecrets []string, kubernetesSecretList *v1.SecretList, clientSet kubernetes.Interface, destEnv string) {
	kubernetesRemove := os.Getenv("KUBERNETESREMOVE")
	if kubernetesRemove == "true" {
		for _, k8sSecret := range kubernetesSecretList.Items {
			if stringSliceContainsString(ripeSecrets, k8sSecret.Name) && hask8sRavenLabel(k8sSecret) {
				log.WithFields(log.Fields{"secret": k8sSecret.Name, "action": "kubernetes.delete", "namespace": destEnv}).Info("Secret no longer available in vault or in git. Removing from Kubernetes namespace.")
				err := clientSet.CoreV1().Secrets(destEnv).Delete(context.TODO(), k8sSecret.Name, metav1.DeleteOptions{})
				if err != nil {
					log.WithFields(log.Fields{"error": err.Error()}).Info("kubernetesRemove clientsetDelete in namespace failed.")

				}
			}
		}
	}

}

func searchKubernetesForResults(ctx context.Context, Mysecret string, c config) {
	kubernetesMonitor := os.Getenv("KUBERNETESMONITOR")
	if kubernetesMonitor == "true" {

		watcher, err := c.Clientset.CoreV1().Secrets(c.destEnv).Watch(context.Background(), metav1.ListOptions{})
		if err != nil {
			log.Fatal("searchKubernetesForResults timeout", err)
		}
		for {
			for event := range watcher.ResultChan() {
				secretObject := event.Object.(*v1.Secret)

				switch event.Type {
				case watch.Added:
					added <- secretObject.ObjectMeta.Name
				}

			}
		}

	}
}

func initKubernetesSearch(secret string, c config) {

	kubernetesMonitor := os.Getenv("KUBERNETESMONITOR")
	if kubernetesMonitor == "true" {

		ctx := context.Background()
		ctxWithTimeout, cancel := context.WithTimeout(ctx, time.Duration(5)*time.Minute)
		go searchKubernetesForResults(ctxWithTimeout, secret, c)
		defer cancel()
	}
}

func monitorMessages(watchlist []string) {
	kubernetesMonitor := os.Getenv("KUBERNETESMONITOR")
	if kubernetesMonitor == "true" {
		log.WithFields(log.Fields{"action": "kubernetes.lookup.secret.start", "secret": watchlist}).Info("Raven starting search for secret in namespace")
		for {
			for i := 0; i < 1; i++ {
				select {
				case addedSecret := <-added:
					if stringSliceContainsString(watchlist, addedSecret) {
						log.WithFields(log.Fields{"action": "kubernetes.lookup.secret.success", "secret": addedSecret}).Info("Raven found secret in kubernetes namespace")
					}
				}
			}
		}
	}
}
