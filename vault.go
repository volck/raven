package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"

	sealedSecretPkg "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
	"github.com/go-git/go-git/v5"
	"github.com/hashicorp/vault/api"
)

func client() (*api.Client, error) {
	config := &api.Config{
		Address:    newConfig.vaultEndpoint,
		HttpClient: http.DefaultClient,
	}
	client, err := api.NewClient(config)
	if err != nil {
		jsonLogger.Error("failed to create vault client",
			"config", config,
			"error", err)
		return nil, err
	}
	client.SetToken(newConfig.token)
	if err != nil {
		jsonLogger.Error("failed to set vault token",
			"config", config,
			"error", err)
		return nil, err
	}
	return client, err
}

func getKVAndCreateSealedSecret(client *api.Client, config config, secretName string) (sealedSecret *sealedSecretPkg.SealedSecret, SingleKVFromVault *api.Secret) {
	input := fmt.Sprintf("%s/", config.secretEngine)
	iterateList(input, client, secretName)

	for path, val := range currentSecrets {
		jsonLogger.Debug("getKVAndCreateSealedSecret", "path", path, "val", val)
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
			jsonLogger.Error("removeFromWorktree remove failed", "err", err)
		}
		jsonLogger.Info("HarvestRipeSecrets found ripe secret. marked for deletion", slog.String("absolutePath", newbase), slog.String("ripeSecret", RipeSecrets[ripe]), slog.String("action", "delete"))
	}
}

func getAllKVs(client *api.Client, config config) (Secret *api.Secret, err error) {
	url := config.secretEngine + "/metadata"

	Secret, err = client.Logical().List(url)
	if err != nil {
		jsonLogger.Error("getAllKVs list error", "error", err)
	}
	return Secret, err
}

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
		currentSecrets[pName] = Secret
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
		jsonLogger.Error("getSingleKV client read error", "error", err)
	}
	return Secret

}

func validToken(client *api.Client) (valid bool) {

	_, err := client.Auth().Token().LookupSelf()
	if err != nil {
		jsonLogger.Error("validateSelfTokenlookupself failed", "error", err)
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

func findRipeAWSSecrets(PreviousKV map[string]*api.Secret, NewKV map[string]*api.Secret) (RipeSecrets map[string]string) {
	RipeSecrets = make(map[string]string)
	if !firstRun(PreviousKV, NewKV) {
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
							theRipeArn := findArnDiff(pvCustomData.(string), nvCustomData.(string))
							fmt.Println(nk, pk)
							RipeSecrets[nk] = theRipeArn
							fmt.Println(RipeSecrets)
						}
					}
				}
			}
		}
	}
	return RipeSecrets
}
