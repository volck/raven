package main

import (
	"encoding/base64"
	log "github.com/sirupsen/logrus"
	"io/fs"
	"math/rand"
	"path/filepath"
	"time"
)

func isBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return false
	}
	return true
}

func makeAbsolutePath(config config, filename fs.FileInfo) (newbase string) {
	base := filepath.Join("declarative", config.destEnv, "sealedsecrets")
	newbase = base + "/" + filename.Name()
	return newbase
}

func sleep() {
	rand.Seed(time.Now().UnixNano())
	max := 30
	min := 15
	sleepTime := rand.Intn(max-min) + min

	//now we sleep randomly
	log.WithFields(log.Fields{"sleepTime": sleepTime}).Debug("Going to sleep.")
	time.Sleep(time.Duration(sleepTime) * time.Second)
	log.WithFields(log.Fields{"sleepTime": sleepTime}).Debug("Sleep done.")
}
