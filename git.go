package main

import (
	"fmt"
	"io/fs"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5/plumbing"

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
		jsonLogger.Error("git show -s", "obj", obj)
	}
	jsonLogger.Info("Harvest of ripe secrets complete", "commitMessage", obj.Message, "When", obj.Committer.When, "action", "delete")
}

func loadSSHKey() (sshKey []byte) {
	sshKeyPath := os.Getenv("SSHKEYPATH")

	if sshKeyPath == "" {
		sshKey, err := os.ReadFile("/secret/sshKey")
		if err != nil {
			jsonLogger.Error("setSSHConfig: unable to read private key", "err", err)
		}
		return sshKey

	} else {
		sshKey, err := os.ReadFile(sshKeyPath)
		fmt.Println()
		if err != nil {
			jsonLogger.Error("setSSHConfig: unable to read private key", "err", err)
		}
		return sshKey

	}
}

func setSigner(sshKey []byte) (signer ssh.Signer) {
	signer, err := ssh.ParsePrivateKey(sshKey)
	if err != nil {
		jsonLogger.Error("setSSHConfig: ParsePrivateKey err", "err", err)
		WriteErrorToTerminationLog("setSSHConfig: unable to read private key")
	}
	return signer
}

func addtoWorktree(item string, worktree *git.Worktree) {
	_, err := worktree.Add(item)
	if err != nil {
		jsonLogger.Error("Raven gitPush:worktree add error", "error", err)
	}
	status, err := getGitStatus(worktree)

	for k, _ := range status {
		secretNameLog = append(secretNameLog, parseGitStatusFileName(k))
		jsonLogger.Info("Raven added secret to git worktree", "action", "request.git.operation.add", "secret", secretNameLog)
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

	log.Debug("GitPush pulling")
	setPullOptions(config, worktree)

	status, err := getGitStatus(worktree)
	if err != nil {
		jsonLogger.Error("getGitStatus error", "status", status)
	}
	if status != nil {
		if !status.IsClean() {
			jsonLogger.Debug("gitPush found that status is not clean, making commit with changes", "isClean", status.IsClean())
			addtoWorktree(".", worktree)

			commitMessage := fmt.Sprintf("Raven updated secret from secret engine: %s and set namespace: %s\n", config.secretEngine, config.destEnv)
			commit, err := makeCommit(worktree, commitMessage)
			if err != nil {
				jsonLogger.Error("GitPush Worktree commit error", "error", err)
			}

			setPushOptions(config, repo, commit)

			obj, err := repo.CommitObject(commit)
			if err != nil {
				jsonLogger.Error("git show -s", "obj", obj)
			}
			jsonLogger.Info("Raven updated files in git", "commitMessage", obj.Message, "When", obj.Committer.When, "action", "request.git.operation.pushed", "secret", secretNameLog)
			genericPostWebHook()
			go monitorMessages(secretNameLog)
			secretNameLog = []string{}
		}
	}

}

func InitializeGitRepo(config config) (r *git.Repository) {
	r, err := git.PlainOpen(config.clonePath)
	if err != nil {
		jsonLogger.Info("HarvestRipeSecrets plainopen failed", "err", err)
	}
	return r
}

func initializeWorkTree(r *git.Repository) (w *git.Worktree) {
	w, err := r.Worktree()
	if err != nil {
		jsonLogger.Error("HarvestRipeSecrets worktree failed", "err", err)
	}
	return
}

func getGitStatus(worktree *git.Worktree) (status git.Status, err error) {
	status, err = worktree.Status()
	if err != nil {
		jsonLogger.Error("HarvestRipeSecret Worktree status failed", "err", err)
	}
	return status, err

}

func makeCommit(worktree *git.Worktree, commitMessage string) (commit plumbing.Hash, err error) {
	status, _ := worktree.Status()
	for k, _ := range status {
		secretName := parseGitStatusFileName(k)
		jsonLogger.Info("Raven Making Commit", "action", "request.git.operation.commit", "secret", secretName)

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
		jsonLogger.Debug("Raven gitPush error", "error", err)
	}
	jsonLogger.Info("Raven updated files in git", "action", "request.git.operation.pushedRemote")

}
func setHTTPSPushOptions(repository *git.Repository, commit plumbing.Hash) {
	err := repository.Push(&git.PushOptions{})
	if err != nil {
		jsonLogger.Error("Raven gitPush error", "error", err)
	}
	// Prints the current HEAD to verify that all worked well.
	obj, err := repository.CommitObject(commit)

	if err != nil {
		jsonLogger.Error("git show -s", "obj", obj)
	}
	jsonLogger.Info("Raven updated files in git", "action", "request.git.operation.pushedRemote", "obj", obj)
	genericPostWebHook()
}

func setHTTPSPullOptions(worktree *git.Worktree) {
	err := worktree.Pull(&git.PullOptions{RemoteName: "origin"})
	if err != nil {
		jsonLogger.Debug("Raven gitPush:Pull error", "error", err)
	}
}

func setSSHPullOptions(worktree *git.Worktree) {
	err := worktree.Pull(&git.PullOptions{RemoteName: "origin", Auth: setSSHConfig()})
	if err != nil {
		jsonLogger.Debug("Raven gitPush:Pull error", "error", err)
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
		jsonLogger.Error("Raven could not determine clone options", "config.RepoUrl", config.repoUrl)
		WriteErrorToTerminationLog(fmt.Sprintf("Raven could not determine clone options(%s)", config.repoUrl))
	}
	return cloneOptions
}

func plainClone(config config, options *git.CloneOptions) {
	remote, err := git.PlainClone(config.clonePath, false, options)
	if err != nil {
		jsonLogger.Debug("Raven GitClone error", "error", err)
	} else {
		head, err := remote.Head()
		if err != nil {
			jsonLogger.Warn("Gitclone Remote.head()", "head", head, "error", err)
		}
	}
	jsonLogger.Info("Raven successfully cloned repository", "repo", config.repoUrl)

}

func getBaseListOfFiles() ([]fs.FileInfo, error) {
	base := filepath.Join(newConfig.clonePath, "declarative", newConfig.destEnv, "sealedsecrets")
	files, err := ioutil.ReadDir(base)
	if err != nil {
		jsonLogger.Error("ioutil.ReadDir() error", "error", err)
	}
	return files, err
}

func removeFileFromWorktree(path string, worktree *git.Worktree) {
	_, err := worktree.Remove(path)
	if err != nil {
		jsonLogger.Error("removeFromWorktree remove failed", "err", err)
	}
}

func removeFilesFromWorkTree(files []fs.FileInfo, worktree *git.Worktree) *git.Worktree {
	for _, f := range files {
		absolutePath := makeAbsolutePath(newConfig, f)
		removeFileFromWorktree(absolutePath, worktree)
		jsonLogger.Info("HarvestRipeSecrets found ripe secret. marked for deletion", "absolutePath", absolutePath, "ripeSecret", f.Name(), "action", "delete")
	}
	return worktree
}

func cleanDeadEntries() {
	jsonLogger.Info("list is nil. We should check if we have a directory full of files that should be deleted from git.")
	repository := InitializeGitRepo(newConfig)
	worktree := initializeWorkTree(repository)
	files, _ := getBaseListOfFiles()

	if len(files) > 0 {
		removeFilesFromWorkTree(files, worktree)
		status, _ := getGitStatus(worktree)

		if !status.IsClean() {

			jsonLogger.Debug("HarvestRipeSecret !status.IsClean()", "worktree", worktree, "status", status)

			commit, _ := makeCommit(worktree, "Raven Removed ripe secret(s) from git")
			setPushOptions(newConfig, repository, commit)
		}
	}
	jsonLogger.Info("Going to sleep now.")
	time.Sleep(30 * time.Second)
}
