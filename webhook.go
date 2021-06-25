package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"encoding/json"
)

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