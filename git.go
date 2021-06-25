package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

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