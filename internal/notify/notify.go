package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/volck/raven/internal/config"
	"github.com/volck/raven/internal/helpers"
)

func GenericPostWebHook(cfg config.Config) {
	webHookUrl, isSet := os.LookupEnv("webhook_url")
	if isSet {
		reqBody, err := json.Marshal(map[string]string{
			"vaultEndpoint": cfg.VaultEndpoint,
			"secretEngine":  cfg.SecretEngine,
			"destEnv":       cfg.DestEnv,
		})
		if err != nil {
			helpers.JsonLogger.Error("genericPostWebHook marshal error", "error", err)
			return
		}
		resp, err := http.Post(webHookUrl,
			"application/json",
			bytes.NewBuffer(reqBody))
		if err != nil {
			helpers.JsonLogger.Error("genericPostWebHook post error", "error", err)
			return
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			helpers.JsonLogger.Error("genericPostWebHook read body error", "error", err)
			return
		}
		fmt.Println(string(body))
	}
}
