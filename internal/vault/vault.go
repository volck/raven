package vault

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/volck/raven/internal/helpers"
)

var jsonLogger = helpers.JsonLogger

func Client(vaultEndpoint string, token string) (*api.Client, error) {
	config := &api.Config{
		Address:    vaultEndpoint,
		HttpClient: http.DefaultClient,
	}
	client, err := api.NewClient(config)
	if err != nil {
		jsonLogger.Error("failed to create vault client",
			"config", config,
			"error", err)
		return nil, err
	}
	client.SetToken(token)
	return client, nil
}

func GetAllKVs(client *api.Client, secretEngine string) (Secret *api.Secret, err error) {
	url := secretEngine + "/metadata"

	Secret, err = client.Logical().List(url)
	if err != nil {
		jsonLogger.Error("getAllKVs list error", "error", err)
	}
	return Secret, err
}

func IterateList(input string, c *api.Client, secretName string, currentSecrets map[string]*api.Secret) *api.Secret {
	if !strings.HasSuffix(input, "/") {
		p := strings.Replace(input, "/", "/data/", 1)
		Secret, err := c.Logical().Read(p)
		if err != nil {
			jsonLogger.Debug("iterateList read error", "error", err)
		}

		secretNameList := strings.Split(p, "/")
		pName := secretNameList[len(secretNameList)-1]
		currentSecrets[pName] = Secret
		return Secret
	}

	p := strings.Replace(input, "/", "/metadata/", 1)

	list, err := c.Logical().List(p)
	if err != nil {
		return nil
	}
	if list.Data == nil {
		return nil
	}

	for _, k := range list.Data["keys"].([]interface{}) {
		p := strings.Replace(input, "/", "/metadata/", 1)
		if strings.HasSuffix(p, "/") {
			p = input + k.(string)
		} else {
			p = p + "/" + k.(string)
		}
		IterateList(p, c, "", currentSecrets)
	}

	return nil
}

func GetSingleKV(client *api.Client, env string, secretname string) (Secret *api.Secret) {
	path := fmt.Sprintf("%s/data/%s", env, secretname)
	Secret, err := client.Logical().Read(path)
	if err != nil {
		jsonLogger.Error("getSingleKV client read error", "error", err)
	}
	return Secret
}

func ValidToken(client *api.Client) bool {
	_, err := client.Auth().Token().LookupSelf()
	if err != nil {
		jsonLogger.Error("validateSelfTokenlookupself failed", "error", err)
		return false
	}
	return true
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

func ExtractCustomKeyFromCustomMetadata(key string, secret *api.Secret) (interface{}, error) {
	customMetadata, found := GetCustomMetadataFromSecret(secret)
	if found {
		if customMetadata != nil {
			if val, ok := customMetadata[key]; ok {
				return val, nil
			}
		}
	}
	return nil, fmt.Errorf("key %s not found in custom metadata", key)
}

func FindRipeAWSSecrets(PreviousKV map[string]*api.Secret, NewKV map[string]*api.Secret) (RipeSecrets map[string]string) {
	RipeSecrets = make(map[string]string)
	if !FirstRun(PreviousKV, NewKV) {
		for nk, nv := range NewKV {
			for pk, pv := range PreviousKV {
				if nk == pk {
					nvCustomData, err := ExtractCustomKeyFromCustomMetadata("AWS_ARN_REF", nv)
					pvCustomData, err := ExtractCustomKeyFromCustomMetadata("AWS_ARN_REF", pv)
					if err != nil {
						jsonLogger.Debug("findRipeAWSSecrets.ExtractCustomKeyFromCustomMetadata failed", slog.Any("error", err))
					}
					if pvCustomData != nil && nvCustomData != nil {
						if pvCustomData != nvCustomData {
							theRipeArn := helpers.FindArnDiff(pvCustomData.(string), nvCustomData.(string))
							RipeSecrets[nk] = theRipeArn
						}
					}
				}
			}
		}
	}
	return RipeSecrets
}

func PickRipeSecrets(PreviousKV map[string]*api.Secret, NewKV map[string]*api.Secret) (RipeSecrets []string) {
	if ListsEmpty(PreviousKV, NewKV) {
	} else if !FirstRun(PreviousKV, NewKV) && !ListsMatch(PreviousKV, NewKV) {
		RipeSecrets = FindRipeSecrets(PreviousKV, NewKV)
	}
	return RipeSecrets
}

func FirstRun(PreviousKV map[string]*api.Secret, NewKV map[string]*api.Secret) bool {
	if PreviousKV == nil || NewKV == nil {
		jsonLogger.Debug("PickRipeSecrets compared lists and found that either of the lists were nil", slog.Any("previousKeys", PreviousKV), slog.Any("newKV", NewKV))
		return true
	}
	return false
}

func ListsEmpty(PreviousKV map[string]*api.Secret, NewKV map[string]*api.Secret) bool {
	return NewKV == nil || PreviousKV == nil
}

func ListsMatch(PreviousKV map[string]*api.Secret, NewKV map[string]*api.Secret) bool {
	if len(PreviousKV) != len(NewKV) {
		return false
	}
	for k := range PreviousKV {
		if _, ok := NewKV[k]; !ok {
			return false
		}
	}
	// Use the original DeepEqual for full comparison
	return true
}

func FindRipeSecrets(PreviousKV map[string]*api.Secret, NewKV map[string]*api.Secret) (RipeSecrets []string) {
	for k := range PreviousKV {
		if !helpers.KeyInDictionary(NewKV, k) {
			jsonLogger.Info("PickRipeSecrets: We have found a ripe secret.", "RipeSecret", k, "action", "delete")
			RipeSecrets = append(RipeSecrets, k)
		}
	}
	return RipeSecrets
}
