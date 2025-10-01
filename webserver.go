package main

import (
	"log/slog"
	"net/http"
	"sync"

	"github.com/hashicorp/vault/api"
)

func forceRefresh(wg *sync.WaitGroup, c config) {
	client, err := client()
	if err != nil {
		jsonLogger.Error("client not initialized", "error", err)

	}
	forcenewSecrets(client, c)
	wg.Done()

}

func forcenewSecrets(client *api.Client, config2 config) {
	var list, errorHere = getAllKVs(client, config2)
	if errorHere != nil {
		jsonLogger.Warn("forceRefresh().getAllKVs failed", "error", errorHere.Error())
	}

	if list != nil {
		for _, secret := range list.Data["keys"].([]interface{}) {
			SealedSecret, _ := getKVAndCreateSealedSecret(client, config2, secret.(string))
			newBase := ensurePathAndReturnWritePath(config2, secret.(string))
			SerializeSealedSecretToFile(SealedSecret, newBase)
			jsonLogger.Info("forceRefresh() rewrote secret", slog.String("secret", secret.(string)), slog.String("newBase", newBase))
		}
	} else {
		jsonLogger.Info("forceRefresh() called, list is empty. doing nothing.")
	}
}

func refreshHandler(c config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var wg sync.WaitGroup
		wg.Add(1)
		go forceRefresh(&wg, c)
		wg.Wait()
		jsonLogger.Info("refreshHandler:forceRefresh() done")
	}
}

func handleRequests(c config) {

	http.HandleFunc("/", refreshHandler(c))
	http.ListenAndServe(":8080", nil)
}
