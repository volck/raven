package main

import (
	"fmt"
	"github.com/go-git/go-git/v5/plumbing"
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

func logHarvestDone(repo *git.Repository, commit plumbing.Hash) {
	obj, err := repo.CommitObject(commit)

	if err != nil {
		log.WithFields(log.Fields{"obj": obj}).Error("git show -s")
	}
	log.WithFields(log.Fields{"commitMessage": obj.Message, "When": obj.Committer.When}).Info("Harvest of ripe secrets complete")
}

func addtoWorktree(item string, worktree *git.Worktree) () {
	_, err := worktree.Add(item)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Raven gitPush:worktree add error")
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

func gitPush(config config) {
	repo := InitializeGitRepo(config)

	worktree := initializeWorkTree(repo)

	// Pull the latest changes from the origin remote and merge into the current branch
	log.Debug("GitPush pulling")
	setPullOptions(config, worktree)

	status, err := getGitStatus(worktree)
	if err != nil {
		log.WithFields(log.Fields{"status": status}).Error("getGitStatus error")
	}
	if !status.IsClean() {
		log.WithFields(log.Fields{"isClean": status.IsClean()}).Debug("gitPush found that status is not clean, making commit with changes")
		addtoWorktree(".", worktree)

		// We can verify the current status of the worktree using the method Status.
		commitMessage := fmt.Sprintf("Raven updated secret in %s", config.secretEngine)
		commit, err := makeCommit(worktree, commitMessage)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("GitPush Worktree commit error")
		}

		// we need to set creds here if its a ssh connection,
		setPushOptions(config, repo, commit)

		// Prints the current HEAD to verify that all worked well.
		obj, err := repo.CommitObject(commit)
		if err != nil {
			log.WithFields(log.Fields{"obj": obj}).Error("git show -s")
		}
		log.WithFields(log.Fields{"commitMessage": obj.Message, "When": obj.Committer.When}).Info("Secret successfully updated")
		genericPostWebHook()
	}

}

func InitializeGitRepo(config config) (r *git.Repository) {
	r, err := git.PlainOpen(config.clonePath)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Info("HarvestRipeSecrets plainopen failed")
	}
	return r
}

func initializeWorkTree(r *git.Repository) (w *git.Worktree) {
	w, err := r.Worktree()
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("HarvestRipeSecrets worktree failed")
	}
	return
}

func getGitStatus(worktree *git.Worktree) (status git.Status, err error) {
	status, err = worktree.Status()

	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Error("HarvestRipeSecret Worktree status failed")
	}
	return status, err

}

func makeCommit(worktree *git.Worktree, commitMessage string) (commit plumbing.Hash, err error) {
	status, _ := worktree.Status()
	log.WithFields(log.Fields{"worktree": worktree, "status": status}).Debug("HarvestRipeSecret !status.IsClean() ")

	commit, err = worktree.Commit(fmt.Sprintf("%s", commitMessage), &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Raven",
			Email: "itte@tæll.no",
			When:  time.Now(),
		},
	})
	return commit, err
}
func setSSHPushOptions(newconfig config, remote *git.Repository) () {

	err := remote.Push(&git.PushOptions{Auth: setSSHConfig()})
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Raven gitPush error")
	}
}
func setHTTPSPushOptions(repository *git.Repository, commit plumbing.Hash) {
	err := repository.Push(&git.PushOptions{})
	if err != nil {
		fmt.Println("the buck stops here at setHTTPSConfig, remote push ")

		log.WithFields(log.Fields{"error": err}).Error("Raven gitPush error")
	}
	// Prints the current HEAD to verify that all worked well.
	obj, err := repository.CommitObject(commit)

	if err != nil {
		log.WithFields(log.Fields{"obj": obj}).Error("git show -s")
	}
	log.WithFields(log.Fields{"obj": obj}).Info("git show -s: commit")
	genericPostWebHook()
}

func setHTTPSPullOptions(worktree *git.Worktree) () {
	err := worktree.Pull(&git.PullOptions{RemoteName: "origin"})
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Raven gitPush:Pull error")
	}
}

func setSSHPullOptions(worktree *git.Worktree) () {
	err := worktree.Pull(&git.PullOptions{RemoteName: "origin", Auth: setSSHConfig()})
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Raven gitPush:Pull error")
	}

}

func setPullOptions(config config, worktree *git.Worktree) {
	if strings.HasPrefix(config.repoUrl, "ssh:") {
		setSSHPullOptions(worktree)

	} else if strings.HasPrefix(config.repoUrl, "http") {
		setHTTPSPullOptions(worktree)
	}
}

func setPushOptions(newConfig config, repository *git.Repository, commit plumbing.Hash) {
	if strings.HasPrefix(newConfig.repoUrl, "ssh:") {
		setSSHPushOptions(newConfig, repository)
	} else if strings.HasPrefix(newConfig.repoUrl, "http") {
		setHTTPSPushOptions(repository, commit)
	}

}
