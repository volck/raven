package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	sealedSecretPkg "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/hashicorp/vault/api"
	"golang.org/x/crypto/ssh"
	"net"
	//"gopkg.in/src-d/go-billy.v4/memfs"
	"github.com/go-git/go-git/v5/plumbing/object"
	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"
	"io/ioutil"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	serializer "k8s.io/apimachinery/pkg/runtime/serializer"
	k8sJson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"math/rand"
	"net/http"
	"os"
	//"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

type config struct {
	vaultEndpoint string
	secretEngine  string
	token         string
	destEnv       string
	pemFile       string
	clonePath     string
	repoUrl       string
}

func initLogging() {
	// Log as JSON instead of the default ASCII formatter.
	log.SetFormatter(&log.JSONFormatter{})

	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	log.SetOutput(os.Stdout)

	loglevel := os.Getenv("LOGLEVEL")

	switch {
	case loglevel == "INFO":
		log.SetLevel(log.InfoLevel)
		log.Infof("Loglevel is: %v", loglevel)
	case loglevel == "DEBUG":
		log.SetLevel(log.DebugLevel)
		log.Infof("Loglevel is: %v", loglevel)
	default:
		log.SetLevel(log.InfoLevel)
		log.Info("No LOGLEVEL specified. Defaulting to Info")

	}

}

/*
We assume program crashed and we need to tell Kubernetes this:
https://kubernetes.io/docs/tasks/debug-application-cluster/determine-reason-pod-failure/
*/

func WriteErrorToTerminationLog(errormsg string) {
	file, _ := os.Create("/dev/termination-log")
	defer file.Close()

	file.WriteString(errormsg)

}

/*
Alive checks for differences between two arrays
*/

func Alive(slice []interface{}, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
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
HarvestRipeSecrets() checks local files based on RipeSecrets returned from PickRipeSecrets() and marks them for deletion.

*/

func HarvestRipeSecrets(RipeSecrets []string, clonePath string, destEnv string) {
	if len(RipeSecrets) == 0 {
	} else {

		r, err := git.PlainOpen(clonePath)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Info("HarvestRipeSecrets plainopen failed")
		}

		w, err := r.Worktree()
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Error("HarvestRipeSecrets worktree failed")
		}
		//Iterate ripe secrets and remove them from worktree and push changes.
		for ripe := range RipeSecrets {
			base := filepath.Join("declarative", destEnv, "sealedsecrets")
			newbase := base + "/" + RipeSecrets[ripe] + ".yaml"
			_, err = w.Remove(newbase)
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Error("HarvestRipeSecrets worktree.Remove failed")
			}
			log.WithFields(log.Fields{"ripeSecret": RipeSecrets[ripe]}).Info("HarvestRipeSecrets found ripe secret. marked for deletion")
		}
		status, err := w.Status()

		if err != nil {
			log.WithFields(log.Fields{
				"err": err,
			}).Error("HarvestRipeSecret Worktree status failed")
		}

		if !status.IsClean() {

			log.WithFields(log.Fields{"worktree": w, "status": status}).Debug("HarvestRipeSecret !status.IsClean() ")

			commit, err := w.Commit(fmt.Sprintf("Raven removed ripe secret from git"), &git.CommitOptions{
				Author: &object.Signature{
					Name:  "Raven",
					Email: "itte@tæll.no",
					When:  time.Now(),
				},
			})

			if strings.HasPrefix(newConfig.repoUrl, "ssh:") {
				err = r.Push(&git.PushOptions{Auth: setSSHConfig()})
				if err != nil {
					panic(err)
				}
			} else {
				err = r.Push(&git.PushOptions{})
				if err != nil {
					log.WithFields(log.Fields{"error": err}).Error("Raven gitPush error")
				}
				// Prints the current HEAD to verify that all worked well.
				obj, err := r.CommitObject(commit)

				if err != nil {
					log.WithFields(log.Fields{"obj": obj}).Error("git show -s")
				}
				log.WithFields(log.Fields{"obj": obj}).Info("git show -s: commit")
				genericPostWebHook()
			}

		}
		log.WithFields(log.Fields{}).Debug("HarvestRipeSecrets done")
	}
}

func setSSHConfig() (auth transport.AuthMethod) {
	sshKey, err := ioutil.ReadFile("/secret/sshKey")
	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Fatal("setSSHConfig: unable to read private key ")
	}

	signer, err := ssh.ParsePrivateKey(sshKey)
	if err != nil {
		WriteErrorToTerminationLog("setSSHConfig: unable to read private key")
		log.WithFields(log.Fields{"err": err}).Fatal("setSSHConfig: ParsePrivateKey err")
	}
	hostKeyCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		return nil
	}

	auth = &gitssh.PublicKeys{User: "git", Signer: signer, HostKeyCallbackHelper: gitssh.HostKeyCallbackHelper{
		HostKeyCallback: hostKeyCallback,
	}}

	return auth

}

func GitClone(LocalPath string, url string) {

	cloneOptions := &git.CloneOptions{}

	if strings.HasPrefix(url, "https://") {
		//we assume a https string with creds in it. e.g. https://someuser:somepass@somehost/some/repository.git

		cloneOptions = &git.CloneOptions{
			URL:      url,
			Progress: os.Stdout,
		}

	} else if strings.HasPrefix(url, "ssh://") {
		//we set up config for ssh with keys. we expect ssh://somehost/some/repo.git

		cloneOptions = &git.CloneOptions{
			URL:      url,
			Progress: os.Stdout,
			Auth:     setSSHConfig(),
		}
	}
	// we do the clone
	log.WithFields(log.Fields{}).Debug("Raven GitClone")

	remote, err := git.PlainClone(LocalPath, false, cloneOptions)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Raven GitClone error")

	} else {
		head, err := remote.Head()
		if err != nil {
			log.WithFields(log.Fields{"head": head, "error": err}).Warn("Gitclone Remote.head()")
		}
		log.WithFields(log.Fields{"head": head}).Debug("Raven GitClone complete")
	}
}

func gitPush(LocalPath string, env string, url string) {
	r, err := git.PlainOpen(LocalPath)
	if err != nil {
		WriteErrorToTerminationLog("plainOpen failed")
		log.WithFields(log.Fields{"error": err}).Error("Raven PlainOpen failed")
	}

	w, err := r.Worktree()
	if err != nil {
		WriteErrorToTerminationLog("gitPush failed")
		log.WithFields(log.Fields{"error": err}).Error("GitPush WorkTree error")
	}

	// Pull the latest changes from the origin remote and merge into the current branch
	log.Debug("GitPush pulling")
	if strings.HasPrefix(url, "ssh:") {
		err = w.Pull(&git.PullOptions{RemoteName: "origin", Auth: setSSHConfig()})
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Debug("Raven gitPush:Pull error")
		}
	} else {
		err = w.Pull(&git.PullOptions{RemoteName: "origin"})
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Debug("Raven gitPush:Pull error")
		}
	}

	status, err := w.Status()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Raven gitPush:worktree status error")
	}
	log.WithFields(log.Fields{"status": status}).Debug("Worktree status")

	if !status.IsClean() {
		log.WithFields(log.Fields{"isClean": status.IsClean()}).Debug("gitPush found that status is not clean, making commit with changes")
		_, err = w.Add(".")
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Raven gitPush:worktree add error")
		}

		// We can verify the current status of the worktree using the method Status.

		commit, err := w.Commit(fmt.Sprintf("Raven updated secrets in %s", env), &git.CommitOptions{
			Author: &object.Signature{
				Name:  "Raven",
				Email: "itte@tæll.no",
				When:  time.Now(),
			},
		})
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("GitPush Worktree commit error")
		}

		// we need to set creds here if its a ssh connection,
		if strings.HasPrefix(url, "ssh:") {
			err = r.Push(&git.PushOptions{Auth: setSSHConfig()})
			if err != nil {
				panic(err)
			}
		} else {
			err = r.Push(&git.PushOptions{})
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Raven gitPush error")
			}
			// Prints the current HEAD to verify that all worked well.
			obj, err := r.CommitObject(commit)
			fmt.Println("head: ", obj)

			if err != nil {
				log.WithFields(log.Fields{"obj": obj}).Error("git show -s")
			}
			log.WithFields(log.Fields{"obj": obj}).Info("git show -s: commit")
			genericPostWebHook()
		}

	}
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

/*
scaffolding for k8s,
createK8sSecret generates k8s secrets based on inputs:
- name: name of secret
- Namespace: k8s namespace
- datafield: data for secret
returns v1.Secret for consumption by SealedSecret
*/

func createK8sSecret(name string, Namespace string, sourceenv string, dataFields *api.Secret) (secret v1.Secret) {
	Annotations := make(map[string]string)
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

	stringdata := make(map[string]string)
	data := make(map[string][]byte)
	isbase64 := func(s string) bool {
		_, err := base64.StdEncoding.DecodeString(s)
		return err == nil
	}
	Annotations["source"] = sourceenv
	if dataFields.Data["data"] == nil {
		log.WithFields(log.Fields{"secret": name}).Info("secret has no data defined in body. skipping it.")
	} else {
		for k, v := range dataFields.Data["data"].(map[string]interface{}) {
			log.WithFields(log.Fields{"key": k, "value": v, "datafields": dataFields.Data["data"]}).Debug("createK8sSecret: dataFields.Data[data] iterate")

			if strings.HasPrefix(v.(string), "base64:") {
				stringSplit := strings.Split(v.(string), ":")
				if isbase64(stringSplit[1]) {
					data[k], _ = base64.StdEncoding.DecodeString(stringSplit[1])
					log.WithFields(log.Fields{"key": k, "value": v, "base64EncodedString": stringSplit[1], "datafields": dataFields.Data["data"]}).Debug("createK8sSecret: dataFields.Data[data] found base64-encoding")
				}
			}
			if k == "raven/description" {
				Annotations[k] = v.(string)
				log.WithFields(log.Fields{"key": k, "value": v, "datafields": dataFields.Data["data"]}).Debug("createK8sSecret: dataFields.Data[data] found raven/description")
			} else {
				stringdata[k] = v.(string)
				log.WithFields(log.Fields{"key": k, "value": v, "datafields": dataFields.Data["data"]}).Debug("createK8sSecret: dataFields.Data[data] catch all. putting value in stringdata[]")
			}

		}
	}
	if dataFields.Data["metadata"] == nil {
		log.WithFields(log.Fields{"secret": name}).Info("secret has no metadata defined in body. skipping it.")
	} else {
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
	}

	secret = v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SealedSecret",
			APIVersion: "bitnami.com/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   Namespace,
			Annotations: Annotations,
		},
		Data:       data,
		StringData: stringdata,
		Type:       "Opaque",
	}

	log.WithFields(log.Fields{"typeMeta": secret.TypeMeta, "objectMeta": secret.ObjectMeta, "data": data, "stringData": stringdata, "secret": secret}).Debug("createK8sSecret: made k8s secret object")
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

func SerializeAndWriteToFile(SealedSecret *sealedSecretPkg.SealedSecret, fullPath string) {
	f, err := os.Create(fullPath)
	if err != nil {
		log.WithFields(log.Fields{"fullPath": fullPath, "error": err.Error()}).Fatal("SerializeAndWriteToFile.Os.Create")
		WriteErrorToTerminationLog(err.Error())
	}
	e := k8sJson.NewYAMLSerializer(k8sJson.DefaultMetaFactory, nil, nil)
	err = e.Encode(SealedSecret, f)
	if err != nil {
		log.WithFields(log.Fields{"fullPath": fullPath, "error": err.Error()}).Fatal("SerializeAndWriteToFile.e.encode")
		WriteErrorToTerminationLog(err.Error())
	}
}

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
ensurePathandreturnWritePath:
* build stringpath
* create path

makes sure that basePath exists for SerializeAndWriteToFile, returning basePath.
*/

func ensurePathandreturnWritePath(clonePath string, destEnv string, secretName string) (basePath string) {
	base := filepath.Join(clonePath, "declarative", destEnv, "sealedsecrets")
	os.MkdirAll(base, os.ModePerm)
	basePath = base + "/" + secretName + ".yaml"
	return
}

var newConfig = config{
	vaultEndpoint: "",
	secretEngine:  "",
	token:         "",
	destEnv:       "",
	pemFile:       "",
	clonePath:     "",
	repoUrl:       "",
}

/*
We need to init the client a lot so this is a helper function which returns a fresh client.
*/

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

func genericPostWebHook() {
	webHookUrl, iSset := os.LookupEnv("webhook_url")
	if iSset {

		reqBody, err := json.Marshal(map[string]string{
			"vaultEndpoint": newConfig.vaultEndpoint,
			"secretEngine":  newConfig.secretEngine,
			"destEnv":       newConfig.destEnv,
		})
		resp, err := http.Post(webHookUrl,
			"application/json",
			bytes.NewBuffer(reqBody))

		if err != nil {
			print(err)
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			print(err)
		}
		fmt.Println(string(body))

	}
}

func forceRefresh(wg *sync.WaitGroup) {
	var list, err = getAllKVs(newConfig.secretEngine, newConfig.token)
	if err != nil {
		log.WithFields(log.Fields{"list": list, "error": err.Error()}).Warn("forceRefresh().getAllKVs failed")
	}
	for _, secret := range list.Data["Keys"].([]string) {
		SealedSecret, _ := getKVAndCreateSealedSecret(newConfig.secretEngine, secret, newConfig.token, newConfig.destEnv, newConfig.pemFile)
		newBase := ensurePathandreturnWritePath(newConfig.clonePath, newConfig.destEnv, secret)
		SerializeAndWriteToFile(SealedSecret, newBase)
		log.WithFields(log.Fields{"secret": secret, "newBase": newBase}).Info("forceRefresh() rewrote secret")
	}
	wg.Done()

}

func refreshHandler(w http.ResponseWriter, r *http.Request) {
	var wg sync.WaitGroup
	wg.Add(1)
	go forceRefresh(&wg)
	wg.Wait()
	log.WithFields(log.Fields{}).Info("refreshHandler:forceRefresh() done")
}

func handleRequests() {

	http.HandleFunc("/forceRefresh", refreshHandler)
	log.Fatal(http.ListenAndServe(":1337", nil))
}

func main() {
	initLogging()
	token := flag.String("token", "", "token used for to grab secrets from Vault")
	secretEngine := flag.String("se", "", "specifies secret engine to grab secrets from in Vault")
	vaultEndpoint := flag.String("vaultendpoint", "", "URL to the Vault installation.")
	pemFile := flag.String("cert", "", "used to create sealed secrets")
	repoUrl := flag.String("repourl", "", "REPO url. e.g. https://uname:pwd@src_control/some/path/somerepo.git")
	clonePath := flag.String("clonepath", "/tmp/clone", "Path in which to clone repo and used for base for appending keys.")
	destEnv := flag.String("dest", "", "destination env in git repository to output SealedSecrets to.")
	flag.Parse()

	visited := true
	flag.VisitAll(func(f *flag.Flag) {
		if f.Value.String() == "" {
			fmt.Printf("[*] -%s not set. Quitting [*]\n", f.Name)
			visited = false
		}

	})
	if visited {
		newConfig.vaultEndpoint = *vaultEndpoint
		newConfig.secretEngine = *secretEngine
		newConfig.token = *token
		newConfig.destEnv = *destEnv
		newConfig.pemFile = *pemFile
		newConfig.clonePath = *clonePath
		newConfig.repoUrl = *repoUrl
		log.WithFields(log.Fields{"config": newConfig}).Debug("Setting newConfig variables. preparing to run. ")
		if validateSelftoken(*vaultEndpoint, *token) {

			// start webserver
			go handleRequests()

			//ensure paths for first time.
			newpath := filepath.Join(*clonePath, *secretEngine)
			err := os.MkdirAll(newpath, os.ModePerm)
			if err != nil {
				log.WithFields(log.Fields{"NewPath": newpath}).Error("os.Mkdir failed when trying to ensure paths for first time")
				WriteErrorToTerminationLog("os.Mkdir failed when trying to ensure paths for first time")
			}

			GitClone(*clonePath, *repoUrl)
			last := &api.Secret{}
			for {
				if validateSelftoken(*vaultEndpoint, *token) {
					log.WithFields(log.Fields{}).Info("Validated Token: grabbing list of secrets")

					var list, err = getAllKVs(newConfig.secretEngine, newConfig.token)
					if err != nil {
						log.WithFields(log.Fields{"error": err}).Error("getAllKVs list error")
					}
					if list == nil {
						log.Info("list is nil. We should check if we have a directory full of files that should be deleted from git.")

						base := filepath.Join(newConfig.clonePath, "declarative", newConfig.destEnv, "sealedsecrets")
						files, err := ioutil.ReadDir(base)
						if err != nil {
							log.WithFields(log.Fields{"error": err}).Error("ioutil.ReadDir() error")
						}

						r, err := git.PlainOpen(newConfig.clonePath)
						if err != nil {
							log.WithFields(log.Fields{"err": err}).Info("HarvestRipeSecrets plainopen failed")
						}
						w, err := r.Worktree()
						if err != nil {
							log.WithFields(log.Fields{"err": err}).Info("HarvestRipeSecrets worktree failed")
						}
						if len(files) > 0 {
							for _, f := range files {
								base := filepath.Join("declarative", newConfig.destEnv, "sealedsecrets")
								newbase := base + "/" + f.Name()
								_, err = w.Remove(newbase)
								if err != nil {
									log.WithFields(log.Fields{"err": err}).Error("HarvestRipeSecrets worktree.Remove failed")
								}
								log.WithFields(log.Fields{"path": newbase, "ripeSecret": f.Name()}).Info("HarvestRipeSecrets found ripe secret. marked for deletion")

							}
							status, err := w.Status()
							if err != nil {
								log.WithFields(log.Fields{"status": status}).Info("Worktree.status failed")
							}

							if !status.IsClean() {

								log.WithFields(log.Fields{"worktree": w, "status": status}).Info("HarvestRipeSecret !status.IsClean() ")

								commit, err := w.Commit(fmt.Sprintf("Raven removed ripe secret from git"), &git.CommitOptions{
									Author: &object.Signature{
										Name:  "Raven",
										Email: "itte@tæll.no",
										When:  time.Now(),
									},
								})

								if strings.HasPrefix(newConfig.repoUrl, "ssh:") {
									err = r.Push(&git.PushOptions{Auth: setSSHConfig()})
									if err != nil {
										panic(err)
									}
								} else {
									err = r.Push(&git.PushOptions{})
									if err != nil {
										log.WithFields(log.Fields{"error": err}).Error("Raven gitPush error")
									}
									// Prints the current HEAD to verify that all worked well.
									obj, err := r.CommitObject(commit)
									fmt.Println("head: ", obj)

									if err != nil {
										log.WithFields(log.Fields{"obj": obj}).Error("git show -s")
									}
									log.WithFields(log.Fields{"obj": obj}).Info("git show -s: commit")
									genericPostWebHook()
								}
							}
						}
						log.Info("Going to sleep now.")
						time.Sleep(30 * time.Second)
					} else {
						for _, secret := range list.Data["keys"].([]interface{}) {

							log.WithFields(log.Fields{"secret": secret}).Debug("Checking secret")
							//make SealedSecrets
							SealedSecret, SingleKVFromVault := getKVAndCreateSealedSecret(newConfig.secretEngine, secret.(string), newConfig.token, newConfig.destEnv, newConfig.pemFile)

							//ensure that path exists in order to write to it later.
							newBase := ensurePathandreturnWritePath(*clonePath, *destEnv, secret.(string))
							if _, err := os.Stat(newBase); os.IsNotExist(err) {
								log.WithFields(log.Fields{"SealedSecret": secret.(string)}).Info(`Creating Sealed Secret`)
								SerializeAndWriteToFile(SealedSecret, newBase)
							} else if !readSealedSecretAndCompareWithVaultStruct(secret.(string), SingleKVFromVault, newBase, newConfig.secretEngine) {
								log.WithFields(log.Fields{"secret": secret}).Debug("readSealedSecretAndCompare: we already have this secret. Vault did not update")
							} else {
								// we need to update the secret.
								log.WithFields(log.Fields{"SealedSecret": secret, "newBase": newBase}).Info("readSealedSecretAndCompare: Found new secret, need to create new sealed secret file")
								SerializeAndWriteToFile(SealedSecret, newBase)
							}

						}
						//..and push new files if there were any. If there are any ripe secrets, delete.
						PickedRipeSecrets := PickRipeSecrets(last, list)
						HarvestRipeSecrets(PickedRipeSecrets, newConfig.clonePath, newConfig.destEnv)
						gitPush(newConfig.clonePath, newConfig.destEnv, *repoUrl)
						log.WithFields(log.Fields{"PickedRipeSecrets": PickedRipeSecrets}).Debug("PickedRipeSecrets list")

						// we save last state of previous list.
						last = list

						// calculate random sleep between 15 and 30 seconds
						rand.Seed(time.Now().UnixNano())
						max := 30
						min := 15
						sleepTime := rand.Intn(max-min) + min

						//now we sleep randomly
						log.WithFields(log.Fields{"sleepTime": sleepTime}).Debug("Going to sleep.")
						time.Sleep(time.Duration(sleepTime) * time.Second)
						log.WithFields(log.Fields{"sleepTime": sleepTime}).Debug("Sleep done.")

					}
				}
			}
		} else {
			log.WithFields(log.Fields{"token": token}).Warn("Token is invalid, need to update. ")
			WriteErrorToTerminationLog("[*] token is invalid, someone needs to update this![*]")
			os.Exit(1)
		}
	}
}
