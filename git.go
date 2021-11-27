package main

import (
	"fmt"
	"github.com/go-git/go-git/v5/plumbing"
	"io/fs"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
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
	log.WithFields(log.Fields{"commitMessage": obj.Message, "When": obj.Committer.When, "action": "delete"}).Info("Harvest of ripe secrets complete")
}

func loadSSHKey() (sshKey []byte) {
	sshKeyPath := os.Getenv("SSHKEYPATH")

	if sshKeyPath == "" {
		sshKey, err := ioutil.ReadFile("/secret/sshKey")
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Fatal("setSSHConfig: unable to read private key ")
		}
		return sshKey

	} else {
		sshKey, err := ioutil.ReadFile(sshKeyPath)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Fatal("setSSHConfig: unable to read private key ")
		}
		return sshKey

	}
}

func setSigner(sshKey []byte) (signer ssh.Signer) {
	signer, err := ssh.ParsePrivateKey(sshKey)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Fatal("setSSHConfig: ParsePrivateKey err")
		WriteErrorToTerminationLog("setSSHConfig: unable to read private key")
	}
	return signer
}

func addtoWorktree(item string, worktree *git.Worktree) {
	_, err := worktree.Add(item)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Raven gitPush:worktree add error")
	}
	status, err := getGitStatus(worktree)

	for k, _ := range status {
		secretNameLog = append(secretNameLog, parseGitStatusFileName(k))
		log.WithFields(log.Fields{"action": "request.git.operation.add", "secret": secretNameLog}).Info("Raven added secret to git worktree")
	}

}
func setSSHConfig() (auth transport.AuthMethod) {
	sshKey := loadSSHKey()
	signer := setSigner(sshKey)
	hostKeyCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		return nil
	}
	auth = &gitssh.PublicKeys{User: "git", Signer: signer, HostKeyCallbackHelper: gitssh.HostKeyCallbackHelper{
		HostKeyCallback: hostKeyCallback,
	}}

	return auth

}

func GitClone(config config) {
	cloneOptions := setCloneOptions(config)
	plainClone(config, cloneOptions)
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
		commitMessage := fmt.Sprintf("Raven updated secret from secret engine: %s and set namespace: %s\n", config.secretEngine, config.destEnv)
		commit, err := makeCommit(worktree, commitMessage)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("GitPush Worktree commit error")
		}

		// we need to set creds here if its a ssh connection.
		setPushOptions(config, repo, commit)

		// Prints the current HEAD to verify that all worked well.
		obj, err := repo.CommitObject(commit)
		if err != nil {
			log.WithFields(log.Fields{"obj": obj}).Error("git show -s")
		}
		log.WithFields(log.Fields{"commitMessage": obj.Message, "When": obj.Committer.When, "action": "request.git.operation.pushed", "secret": secretNameLog}).Info("Raven updated files in git")
		genericPostWebHook()
		secretNameLog = []string{}
		go monitorMessages(added,deleted)
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
	for k, _ := range status {
		secretName := parseGitStatusFileName(k)
		log.WithFields(log.Fields{"action": "request.git.operation.commit", "secret": secretName}).Info("Raven Making Commit")

	}
	commit, err = worktree.Commit(fmt.Sprintf("%s", commitMessage), &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Raven",
			Email: "itte@tæll.no",
			When:  time.Now(),
		},
	})
	return commit, err
}
func setSSHPushOptions(newconfig config, remote *git.Repository) {

	err := remote.Push(&git.PushOptions{Auth: setSSHConfig()})
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Raven gitPush error")
	}
	log.WithFields(log.Fields{"action": "request.git.operation.pushedRemote"}).Info("Raven updated files in git")

}
func setHTTPSPushOptions(repository *git.Repository, commit plumbing.Hash) {
	err := repository.Push(&git.PushOptions{})
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Raven gitPush error")
	}
	// Prints the current HEAD to verify that all worked well.
	obj, err := repository.CommitObject(commit)

	if err != nil {
		log.WithFields(log.Fields{"obj": obj}).Error("git show -s")
	}
	log.WithFields(log.Fields{"action": "request.git.operation.pushedRemote", "obj": obj}).Info("Raven updated files in git")
	genericPostWebHook()
}

func setHTTPSPullOptions(worktree *git.Worktree) {
	err := worktree.Pull(&git.PullOptions{RemoteName: "origin"})
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Raven gitPush:Pull error")
	}
}

func setSSHPullOptions(worktree *git.Worktree) {
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

func setSSHCloneOptions(config config) *git.CloneOptions {

	cloneOptions := &git.CloneOptions{
		URL:  config.repoUrl,
		Auth: setSSHConfig(),
	}
	return cloneOptions
}

func setHTTPSCloneOptions(config config) *git.CloneOptions {

	cloneOptions := &git.CloneOptions{
		URL: config.repoUrl,
	}
	return cloneOptions
}

func setCloneOptions(config config) (cloneOptions *git.CloneOptions) {
	if strings.HasPrefix(config.repoUrl, "https://") {
		cloneOptions = setHTTPSCloneOptions(config)

	} else if strings.HasPrefix(config.repoUrl, "ssh://") {
		//we set up config for ssh with keys. we expect ssh://somehost/some/repo.git
		cloneOptions = setSSHCloneOptions(config)
	} else {
		log.WithFields(log.Fields{"config.RepoUrl": config.repoUrl}).Fatalf("Raven could not determine clone options")
		WriteErrorToTerminationLog(fmt.Sprintf("Raven could not determine clone options(%s)", config.repoUrl))
	}
	return cloneOptions
}

func plainClone(config config, options *git.CloneOptions) {
	remote, err := git.PlainClone(config.clonePath, false, options)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Raven GitClone error")
	} else {
		head, err := remote.Head()
		if err != nil {
			log.WithFields(log.Fields{"head": head, "error": err}).Warn("Gitclone Remote.head()")
		}
	}
	log.WithFields(log.Fields{"repo": config.repoUrl}).Info("Raven successfully cloned repository")

}

func getBaseListOfFiles() ([]fs.FileInfo, error) {
	base := filepath.Join(newConfig.clonePath, "declarative", newConfig.destEnv, "sealedsecrets")
	files, err := ioutil.ReadDir(base)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("ioutil.ReadDir() error")
	}
	return files, err
}

func removeFileFromWorktree(path string, worktree *git.Worktree) {
	_, err := worktree.Remove(path)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("removeFromWorktree remove failed")
	}
}

func removeFilesFromWorkTree(files []fs.FileInfo, worktree *git.Worktree) *git.Worktree {
	for _, f := range files {
		absolutePath := makeAbsolutePath(newConfig, f)
		removeFileFromWorktree(absolutePath, worktree)
		log.WithFields(log.Fields{"absolutePath": absolutePath, "ripeSecret": f.Name(), "action": "delete"}).Info("HarvestRipeSecrets found ripe secret. marked for deletion")
	}
	return worktree
}

func cleanDeadEntries() {
	log.Info("list is nil. We should check if we have a directory full of files that should be deleted from git.")
	repository := InitializeGitRepo(newConfig)
	worktree := initializeWorkTree(repository)
	files, _ := getBaseListOfFiles()

	if len(files) > 0 {
		removeFilesFromWorkTree(files, worktree)
		status, _ := getGitStatus(worktree)

		if !status.IsClean() {

			log.WithFields(log.Fields{"worktree": worktree, "status": status}).Debug("HarvestRipeSecret !status.IsClean() ")

			commit, _ := makeCommit(worktree, "Raven Removed ripe secret(s) from git")
			setPushOptions(newConfig, repository, commit)
		}
	}
	log.Info("Going to sleep now.")
	time.Sleep(30 * time.Second)
}
