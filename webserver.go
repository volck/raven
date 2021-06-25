package main

import (
	"net/http"
	"sync"

	log "github.com/sirupsen/logrus"
)

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