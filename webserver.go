package main

import (
	"net/http"
	"sync"

	log "github.com/sirupsen/logrus"
)

func forceRefresh(wg *sync.WaitGroup) {
	client, err := client()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Fatal("client not initialized")

	}
	var list, errorHere = getAllKVs(client, newConfig)
	if errorHere != nil {
		log.WithFields(log.Fields{"list": list, "error": errorHere.Error()}).Warn("forceRefresh().getAllKVs failed")
	}
	for _, secret := range list.Data["Keys"].([]string) {
		SealedSecret, _ := getKVAndCreateSealedSecret(client,newConfig, secret)
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
