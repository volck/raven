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
	yaml "gopkg.in/yaml.v2"
	"io/ioutil"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	serializer "k8s.io/apimachinery/pkg/runtime/serializer"
	k8sJson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"log"
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

type kvstore struct {
	RequestID     string `json:"request_id"`
	LeaseID       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          struct {
		Keys []string `json:"keys"`
	} `json:"data"`
	WrapInfo interface{} `json:"wrap_info"`
	Warnings interface{} `json:"warnings"`
	Auth     interface{} `json:"auth"`
}

type tokenValid struct {
	RequestID     string `json:"request_id"`
	LeaseID       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          struct {
		Accessor       string      `json:"accessor"`
		CreationTime   int         `json:"creation_time"`
		CreationTTL    int         `json:"creation_ttl"`
		DisplayName    string      `json:"display_name"`
		EntityID       string      `json:"entity_id"`
		ExpireTime     interface{} `json:"expire_time"`
		ExplicitMaxTTL int         `json:"explicit_max_ttl"`
		ID             string      `json:"id"`
		Meta           interface{} `json:"meta"`
		NumUses        int         `json:"num_uses"`
		Orphan         bool        `json:"orphan"`
		Path           string      `json:"path"`
		Policies       []string    `json:"policies"`
		TTL            int         `json:"ttl"`
		Type           string      `json:"type"`
	} `json:"data"`
	WrapInfo interface{} `json:"wrap_info"`
	Warnings interface{} `json:"warnings"`
	Auth     interface{} `json:"auth"`
	Errors   []string    `json:"errors"`
}

type singleKV struct {
	RequestID     string `json:"request_id"`
	LeaseID       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          struct {
		Data     map[string]interface{} `json:"data"`
		Metadata map[string]interface{} `json:"metadata"`
	} `json:"data"`
	WrapInfo interface{} `json:"wrap_info"`
	Warnings interface{} `json:"warnings"`
	Auth     interface{} `json:"auth"`
}

type config struct {
	vaultEndpoint string
	secretEngine  string
	token         string
	destEnv       string
	pemFile       string
	clonePath     string
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

func CheckIfError(err error) {
	if err != nil {
		fmt.Printf("err: %v \n", err)
	}
}

/*
Alive checks for differences between two arrays
*/

func Alive(slice []string, val string) bool {
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

func PickRipeSecrets(PreviousKV kvstore, NewKV kvstore) (RipeSecrets []string) {

	fmt.Printf("[*] PickRipeSecrets: Previous: %v \n New: %v [*] \n", PreviousKV.Data.Keys, NewKV.Data.Keys)
	if len(PreviousKV.Data.Keys) == 0 || len(NewKV.Data.Keys) == 0 {
		// we assume this is our first run so we do not know difference yet.
	} else if reflect.DeepEqual(PreviousKV.Data.Keys, NewKV.Data.Keys) {
		fmt.Println("PickRipeSecrets: Lists match.")
	} else {
		for secret := range PreviousKV.Data.Keys {
			isAlive := Alive(NewKV.Data.Keys, PreviousKV.Data.Keys[secret])
			if !isAlive {
				fmt.Printf("[*] gosh darn it,  %s is ripe for pickin' [*] ", PreviousKV.Data.Keys[secret])
				RipeSecrets = append(RipeSecrets, PreviousKV.Data.Keys[secret])
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
		CheckIfError(err)

		w, err := r.Worktree()
		CheckIfError(err)

		//Iterate ripe secrets and remove them from worktree and push changes.
		for ripe := range RipeSecrets {
			base := filepath.Join("declarative", destEnv, "sealedsecrets")
			newbase := base + "/" + RipeSecrets[ripe] + ".yaml"
			_, err = w.Remove(newbase)
			CheckIfError(err)
			fmt.Printf("[*] %s is ripe, we mark it for deletion [*] \n", newbase)
		}
		status, err := w.Status()
		CheckIfError(err)
		if !status.IsClean() {
			commit, err := w.Commit(fmt.Sprintf("Raven removed ripe secret from git"), &git.CommitOptions{
				Author: &object.Signature{
					Name:  "Raven",
					Email: "itte@tæll.no",
					When:  time.Now(),
				},
			})
			err = r.Push(&git.PushOptions{})
			obj, err := r.CommitObject(commit)
			CheckIfError(err)
			fmt.Printf("commit: %s \n", obj)

		}
		fmt.Printf("[*] HarvestRipeSecrets done [*] \n")
	}
}

func setSSHConfig() (auth transport.AuthMethod) {

	sshKey, err := ioutil.ReadFile("/secret/sshKey")



	if err != nil {
		log.Fatalf("unable to read private key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(sshKey)
	if err != nil {
		return
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

	fmt.Printf("[*] Raven GitClone [*] \n")

	remote, err := git.PlainClone(LocalPath, false, cloneOptions)
	if err != nil {
		fmt.Printf("gitclone: %s \n", err)

	} else {
		CheckIfError(err)
		head, _ := remote.Head()
		fmt.Printf("[*] Raven GitClone complete, current HEAD: %s [*] \n", head)
	}
}

func gitPush(LocalPath string, env string, url string) {
	fmt.Println("this is GitPush. ")
	r, err := git.PlainOpen(LocalPath)
	if err != nil {
		fmt.Printf("plainOpen failed here, %v \n", err)
	}

	w, err := r.Worktree()
	CheckIfError(err)

	// Pull the latest changes from the origin remote and merge into the current branch
	fmt.Println("[*] gitPush is now pulling [*]")
	if strings.HasPrefix(url, "ssh:") {
		err = w.Pull(&git.PullOptions{RemoteName: "origin", Auth: setSSHConfig()})
		if err != nil {
			fmt.Printf("err PULLING: %v \n", err.Error())
		}
	} else {
		err = w.Pull(&git.PullOptions{RemoteName: "origin"})
		if err != nil {
			fmt.Printf("err PULLING: %v \n", err.Error())
		}
	}

	status, err := w.Status()
	CheckIfError(err)
	fmt.Println(status)
	if !status.IsClean() {
		fmt.Printf("[*] gitPush found that status is not clean, making commit with changes [*] \n")
		_, err = w.Add(".")
		CheckIfError(err)

		// We can verify the current status of the worktree using the method Status.

		commit, err := w.Commit(fmt.Sprintf("Raven updated secrets in %s", env), &git.CommitOptions{
			Author: &object.Signature{
				Name:  "Raven",
				Email: "itte@tæll.no",
				When:  time.Now(),
			},
		})

		// we need to set creds here if its a ssh connection,
		if strings.HasPrefix(url, "ssh:") {
			err = r.Push(&git.PushOptions{Auth: setSSHConfig()})
			if err != nil {
				panic(err)
			}
		} else {
			err = r.Push(&git.PushOptions{})
			if err != nil {
				fmt.Printf("err PULLING: %v \n", err.Error())
			}
			// Prints the current HEAD to verify that all worked well.

			fmt.Println("git show -s")
			obj, err := r.CommitObject(commit)
			CheckIfError(err)
			fmt.Printf("commit: %s \n", obj)
			genericPostWebHook()
		}
		fmt.Println("[*] gitPush finished [*]")
	}
}

/*
getallKvs parameters:
enviroment(i.e qa??, dev??)

returns struct kvstore

*/

func getAllKVs(vaultEndPoint string, env string, token string) (kv kvstore) {
	url := vaultEndPoint + "/v1/" + env + "/metadata"
	client := &http.Client{}
	req, err := http.NewRequest("LIST", url, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	bodyText, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal([]byte(bodyText), &kv)
	if err != nil {
		fmt.Println("error-> ", err)
	} else {
		return
	}
	return
}

/*
getsingleKV() used to iterate struct from getAllKVs(), takes secretname as input, returns struct for single secret. Requires uniform data.
*/

func getSingleKV(vaultEndPoint string, env string, secretname string, token string) (kv singleKV) {
	url := vaultEndPoint + "/v1/" + env + "/data/" + secretname

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	bodyText, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal([]byte(bodyText), &kv)
	if err != nil {
		fmt.Println("error-> ", err)
	} else {
		return
	}
	return

}
func RenewSelfToken(token string, vaultEndpoint string) {
	config := &api.Config{
		Address:    vaultEndpoint,
		HttpClient: http.DefaultClient,
	}
	client, err := api.NewClient(config)
	if err != nil {
		fmt.Println(err)
	}
	client.SetToken(token)
	if err != nil {
		fmt.Println(err)
	}
	clientToken, err := client.Auth().Token().RenewSelf(300) // renew for 5 more minutes.
	fmt.Println(clientToken)
	if err != nil {
		fmt.Printf("err, %s \n", err.Error())
	}

}

/* validateSelftoken() takes token as input,
returns false if tokens has errors or is invalid.
*/

func validateSelftoken(vaultEndPoint string, token string) (valid bool) {

	url := vaultEndPoint + "/v1/auth/token/lookup-self"

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	bodyText, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	var tokenreturn tokenValid
	err = json.Unmarshal([]byte(bodyText), &tokenreturn)
	if err != nil {
		fmt.Println("error-> ", err)
	} else {
		if len(tokenreturn.Errors) == 0 {
			fmt.Printf("[*] Token is valid. TTL: %v  [*] \n", tokenreturn.Data.TTL)
			valid = true
			if tokenreturn.Data.TTL < 100 {
				RenewSelfToken(token, vaultEndPoint)
			}
			return
		} else {
			valid = false
			return
		}
	}
	return
}

/*
scaffolding for k8s,
createK8sSecret generates k8s secrets based on inputs:
- name: name of secret
- Namespace: k8s namespace
- datafield: data for secret
returns v1.Secret for consumption by SealedSecret
*/

func createK8sSecret(name string, Namespace string, sourceenv string, dataFields singleKV) (secret v1.Secret) {
	Annotations := make(map[string]string)
	for k, v := range dataFields.Data.Metadata {
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
	for k, v := range dataFields.Data.Data {
		// we handle descriptions for KVs here, in order to show which secrets are handled by which SSG.
		if k == "raven/description" {
			Annotations[k] = v.(string)
		} else {
			if strings.HasPrefix(v.(string), "base64:") {
				stringSplit := strings.Split(v.(string), ":")
				if isbase64(stringSplit[1]) {
					data[k], _ = base64.StdEncoding.DecodeString(stringSplit[1])
				}
			} else {
				stringdata[k] = v.(string)
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
		fmt.Println(err)
	}

	block, _ := pem.Decode([]byte(read))
	if block == nil {
		WriteErrorToTerminationLog("failed to parse PEM block containing the public key")
	}
	var pub *x509.Certificate

	pub, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		WriteErrorToTerminationLog("failed to parse DER encoded public key: " + err.Error())
	}
	var codecs serializer.CodecFactory
	rsaPublicKey, _ := pub.PublicKey.(*rsa.PublicKey)
	sealedSecret, err = sealedSecretPkg.NewSealedSecret(codecs, rsaPublicKey, k8ssecret)
	// apparently we need to specifically assign these fields.
	sealedSecret.TypeMeta = k8ssecret.TypeMeta
	sealedSecret.ObjectMeta = k8ssecret.ObjectMeta
	return
}

func SerializeAndWriteToFile(SealedSecret *sealedSecretPkg.SealedSecret, fullPath string) {
	f, err := os.Create(fullPath)
	if err != nil {
		fmt.Println(err)
	}
	e := k8sJson.NewYAMLSerializer(k8sJson.DefaultMetaFactory, nil, nil)
	err = e.Encode(SealedSecret, f)
	if err != nil {
		WriteErrorToTerminationLog(err.Error())
	}
}

func readSealedSecretAndCompareWithVaultStruct(secret string, kv singleKV, filepointer string, secretEngine string) (NeedUpdate bool) {
	/*
		readSealedSecretAndCompareWithVaultStruct takes a vault KV as parameter as well as a filepointer pointing to a local yaml file.

	*/
	NeedUpdate = false
	VaultTimeStamp := kv.Data.Metadata["created_time"]

	//grab SealedSecret file
	data, err := ioutil.ReadFile(filepointer)
	if err != nil {
		log.Fatalln(err)
	}
	//unmarshal it into a interface
	v := make(map[string]interface{})
	err = yaml.Unmarshal(data, &v)
	if err != nil {
		log.Fatalln(err)
	}
	// hacky way of getting variable
	if _, ok := v["metadata"]; ok {
		if !ok {
			NeedUpdate = true
		}
		SealedSecretTime := v["metadata"].(map[interface{}]interface{})["annotations"].(map[interface{}]interface{})["created_time"]
		SealedSecretSource := v["metadata"].(map[interface{}]interface{})["annotations"].(map[interface{}]interface{})["source"]
		if VaultTimeStamp == SealedSecretTime || SealedSecretSource != secretEngine {
			return
		} else {
			fmt.Printf("[*] Changes were made to %s:  Vault: %s \t SealedSecretTime: %s [*] \n [*] \n", secret, VaultTimeStamp, SealedSecretTime)
			NeedUpdate = true
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
func getKVAndCreateSealedSecret(vaultEndpoint string, secretEngine string, secretName string, token string, destEnv string, pemFile string) (SealedSecret *sealedSecretPkg.SealedSecret, SingleKVFromVault singleKV) {
	SingleKVFromVault = getSingleKV(vaultEndpoint, secretEngine, secretName, token)
	k8sSecret := createK8sSecret(secretName, destEnv, secretEngine, SingleKVFromVault)
	SealedSecret = createSealedSecret(pemFile, &k8sSecret)
	return
}

/*
ensurePathandreturnWritePath:
* build stringpath
* create path

makes sure that basePath exists for SerializeAndWriteToFile, returning basePath.
*/

func ensurePathandreturnWritePath(clonePath string, destEnv string, secretName string, ) (basePath string) {
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
	clonePath:     ""}

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
	var list = getAllKVs(newConfig.vaultEndpoint, newConfig.secretEngine, newConfig.token)
	for _, secret := range list.Data.Keys {
		SealedSecret, _ := getKVAndCreateSealedSecret(newConfig.vaultEndpoint, newConfig.secretEngine, secret, newConfig.token, newConfig.destEnv, newConfig.pemFile)
		newBase := ensurePathandreturnWritePath(newConfig.clonePath, newConfig.destEnv, secret)
		SerializeAndWriteToFile(SealedSecret, newBase)
		fmt.Printf("to the victor goes the spoils: rewrote %s \n", secret)
	}
	wg.Done()

}

func refreshHandler(w http.ResponseWriter, r *http.Request) {
	var wg sync.WaitGroup
	wg.Add(1)
	go forceRefresh(&wg)
	wg.Wait()
	fmt.Fprintf(w, "forceRefresh done.")
}

func handleRequests() {

	http.HandleFunc("/forceRefresh", refreshHandler)
	log.Fatal(http.ListenAndServe(":1337", nil))
}

func main() {
	token := flag.String("token", "", "token used for to grab secrets from Vault")
	secretEngine := flag.String("se", "", "specifies secret engine to grab secrets from in Vault")
	vaultEndpoint := flag.String("vaultendpoint", "https://vault.norsk-tipping.no", "URL to the Vault installation.")
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
		if validateSelftoken(*vaultEndpoint, *token) {
			newConfig.vaultEndpoint = *vaultEndpoint
			newConfig.secretEngine = *secretEngine
			newConfig.token = *token
			newConfig.destEnv = *destEnv
			newConfig.pemFile = *pemFile
			newConfig.clonePath = *clonePath
			// start webserver
			go handleRequests()

			//ensure paths for first time.
			newpath := filepath.Join(*clonePath, *secretEngine)
			err := os.MkdirAll(newpath, os.ModePerm)
			CheckIfError(err)
			GitClone(*clonePath, *repoUrl)
			last := kvstore{}
			for {
				t := time.Now()

				if validateSelftoken(*vaultEndpoint, *token) {
					timeStamp := t.Format(time.Stamp)
					fmt.Printf("[%s] Getting list of secrets\n", timeStamp)
					var list = getAllKVs(*vaultEndpoint, *secretEngine, *token)
					for secret := range list.Data.Keys {
						fmt.Printf("[*] Checking %s [*]\n", list.Data.Keys[secret])

						//make SealedSecrets
						SealedSecret, SingleKVFromVault := getKVAndCreateSealedSecret(*vaultEndpoint, *secretEngine, list.Data.Keys[secret], *token, *destEnv, *pemFile)

						//ensure that path exists in order to write to it later.
						newBase := ensurePathandreturnWritePath(*clonePath, *destEnv, list.Data.Keys[secret])
						if _, err := os.Stat(newBase); os.IsNotExist(err) {
							fmt.Printf("%s does not exist, creating YAML \n", newBase)
							SerializeAndWriteToFile(SealedSecret, newBase)
						} else if !readSealedSecretAndCompareWithVaultStruct(list.Data.Keys[secret], SingleKVFromVault, newBase, *secretEngine) {
							//readSealedSecretAndCompare returns true, meaning SealedSecret matches Vault KV, we assume we already have this secret and that Vault did not update.
						} else {
							// we need to update the secret.
							fmt.Printf("[*] Mismatch between sealed secret and vault secret. Creating new sealed secret file. [*]\n")
							SerializeAndWriteToFile(SealedSecret, newBase)
						}
					}
					//..and push new files if there were any. If there are any ripe secrets, delete.
					gitPush(*clonePath, *destEnv, *repoUrl)
					PickedRipeSecrets := PickRipeSecrets(last, list)
					HarvestRipeSecrets(PickedRipeSecrets, *clonePath, *destEnv)
					// we save last state of previous list.
					last = list

					// calculate random sleep between 15 and 30 seconds
					rand.Seed(time.Now().UnixNano())
					max := 30
					min := 15
					sleepTime := rand.Intn(max-min) + min

					//now we sleep randomly
					time.Sleep(time.Duration(sleepTime) * time.Second)

				} else {
					fmt.Println("[*] token is invalid, someone needs to update this![*]")
					WriteErrorToTerminationLog("[*] token is invalid, someone needs to update this![*]")
					os.Exit(1)
				}
			}
		} else {
			fmt.Println("[*] token is invalid [*]")
			WriteErrorToTerminationLog("[*] token is invalid, someone needs to update this![*]")
			os.Exit(1)
		}
	}
}
