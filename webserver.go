package main

import (
	"github.com/hashicorp/vault/api"
	"net/http"
	"sync"

	log "github.com/sirupsen/logrus"
)

func forceRefresh(wg *sync.WaitGroup, c config) {
	client, err := client()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Fatal("client not initialized")

	}
	forcenewSecrets(client, c)
	wg.Done()

}

func forcenewSecrets(client *api.Client, config2 config) {
	var list, errorHere = getAllKVs(client, config2)
	if errorHere != nil {
		log.WithFields(log.Fields{"list": list, "error": errorHere.Error()}).Warn("forceRefresh().getAllKVs failed")
	}
	if list != nil {
		for _, secret := range list.Data["keys"].([]interface{}) {
			SealedSecret, _ := getKVAndCreateSealedSecret(client, config2, secret.(string))
			newBase := ensurePathandreturnWritePath(config2, secret.(string))
			SerializeAndWriteToFile(SealedSecret, newBase)
			log.WithFields(log.Fields{"secret": secret, "newBase": newBase}).Info("forceRefresh() rewrote secret")

		}
	} else {
		log.WithFields(log.Fields{"secretList": list, }).Info("forceRefresh() called, list is empty. doing nothing.")
	}
}

func refreshHandler(c config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var wg sync.WaitGroup
		wg.Add(1)
		go forceRefresh(&wg, c)
		wg.Wait()
		log.WithFields(log.Fields{}).Info("refreshHandler:forceRefresh() done")
	}
}

func handleRequests(c config) {

	http.HandleFunc("/", refreshHandler(c))
	http.ListenAndServe(":8080", nil)
}
