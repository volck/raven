package gitops

import (
	"fmt"
	"io/fs"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/volck/raven/internal/config"
	"github.com/volck/raven/internal/helpers"
	"golang.org/x/crypto/ssh"
)

var jsonLogger = helpers.JsonLogger

func LogHarvestDone(repo *git.Repository, commit plumbing.Hash) {
	obj, err := repo.CommitObject(commit)
	if err != nil {
		jsonLogger.Error("git show -s", "obj", obj)
	}
	jsonLogger.Info("Harvest of ripe secrets complete", "commitMessage", obj.Message, "When", obj.Committer.When, "action", "delete")
}

func LoadSSHKey() (sshKey []byte) {
	sshKeyPath := os.Getenv("SSHKEYPATH")

	if sshKeyPath == "" {
		sshKey, err := os.ReadFile("/secret/sshKey")
		if err != nil {
			jsonLogger.Error("setSSHConfig: unable to read private key", "err", err)
		}
		return sshKey
	}
	sshKey, err := os.ReadFile(sshKeyPath)
	if err != nil {
		jsonLogger.Error("setSSHConfig: unable to read private key", "err", err)
	}
	return sshKey
}

func SetSigner(sshKey []byte) ssh.Signer {
	signer, err := ssh.ParsePrivateKey(sshKey)
	if err != nil {
		jsonLogger.Error("setSSHConfig: ParsePrivateKey err", "err", err)
		helpers.WriteErrorToTerminationLog("setSSHConfig: unable to read private key")
	}
	return signer
}

func AddToWorktree(item string, worktree *git.Worktree, destEnv string) []string {
	var secretNameLog []string
	_, err := worktree.Add(item)
	if err != nil {
		jsonLogger.Error("Raven gitPush:worktree add error", "error", err)
	}
	status, _ := GetGitStatus(worktree)
	for k := range status {
		name := helpers.ParseGitStatusFileName(destEnv, k)
		secretNameLog = append(secretNameLog, name)
		jsonLogger.Info("Raven added secret to git worktree", "action", "request.git.operation.add", "secret", name)
	}
	return secretNameLog
}

func SetSSHConfig() transport.AuthMethod {
	sshKey := LoadSSHKey()
	signer := SetSigner(sshKey)
	hostKeyCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		return nil
	}
	auth := &gitssh.PublicKeys{User: "git", Signer: signer, HostKeyCallbackHelper: gitssh.HostKeyCallbackHelper{
		HostKeyCallback: hostKeyCallback,
	}}
	return auth
}

func GitClone(cfg config.Config) {
	cloneOptions := SetCloneOptions(cfg)
	PlainClone(cfg, cloneOptions)
}

func GitPush(cfg config.Config) {
	var secretNameLog []string
	repo := InitializeGitRepo(cfg)
	worktree := InitializeWorkTree(repo)

	SetPullOptions(cfg, worktree)

	status, err := GetGitStatus(worktree)
	if err != nil {
		jsonLogger.Error("getGitStatus error", "status", status)
	}
	if status != nil {
		if !status.IsClean() {
			jsonLogger.Debug("gitPush found that status is not clean, making commit with changes", "isClean", status.IsClean())
			secretNameLog = AddToWorktree(".", worktree, cfg.DestEnv)

			commitMessage := fmt.Sprintf("Raven updated secret from secret engine: %s and set namespace: %s\n", cfg.SecretEngine, cfg.DestEnv)
			commit, err := MakeCommit(worktree, commitMessage, cfg.DestEnv)
			if err != nil {
				jsonLogger.Error("GitPush Worktree commit error", "error", err)
			}

			SetPushOptions(cfg, repo, commit)

			obj, err := repo.CommitObject(commit)
			if err != nil {
				jsonLogger.Error("git show -s", "obj", obj)
			}
			jsonLogger.Info("Raven updated files in git", "commitMessage", obj.Message, "When", obj.Committer.When, "action", "request.git.operation.pushed", "secret", secretNameLog)
		}
	}
}

func InitializeGitRepo(cfg config.Config) *git.Repository {
	r, err := git.PlainOpen(cfg.ClonePath)
	if err != nil {
		jsonLogger.Info("InitializeGitRepo plainopen failed", "err", err)
	}
	return r
}

func InitializeWorkTree(r *git.Repository) *git.Worktree {
	w, err := r.Worktree()
	if err != nil {
		jsonLogger.Error("InitializeWorkTree worktree failed", "err", err)
	}
	return w
}

func GetGitStatus(worktree *git.Worktree) (git.Status, error) {
	status, err := worktree.Status()
	if err != nil {
		jsonLogger.Error("GetGitStatus failed", "err", err)
	}
	return status, err
}

func MakeCommit(worktree *git.Worktree, commitMessage string, destEnv string) (plumbing.Hash, error) {
	status, _ := worktree.Status()
	for k := range status {
		secretName := helpers.ParseGitStatusFileName(destEnv, k)
		jsonLogger.Info("Raven Making Commit", "action", "request.git.operation.commit", "secret", secretName)
	}
	commit, err := worktree.Commit(commitMessage, &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Raven",
			Email: "itte@tæll.no",
			When:  time.Now(),
		},
	})
	return commit, err
}

func SetSSHPushOptions(cfg config.Config, remote *git.Repository) {
	err := remote.Push(&git.PushOptions{Auth: SetSSHConfig()})
	if err != nil {
		jsonLogger.Debug("Raven gitPush error", "error", err)
	}
	jsonLogger.Info("Raven updated files in git", "action", "request.git.operation.pushedRemote")
}

func SetHTTPSPushOptions(repository *git.Repository, commit plumbing.Hash) {
	err := repository.Push(&git.PushOptions{})
	if err != nil {
		jsonLogger.Error("Raven gitPush error", "error", err)
	}
	obj, err := repository.CommitObject(commit)
	if err != nil {
		jsonLogger.Error("git show -s", "obj", obj)
	}
	jsonLogger.Info("Raven updated files in git", "action", "request.git.operation.pushedRemote", "obj", obj)
}

func SetHTTPSPullOptions(worktree *git.Worktree) {
	err := worktree.Pull(&git.PullOptions{RemoteName: "origin"})
	if err != nil {
		jsonLogger.Debug("Raven gitPush:Pull error", "error", err)
	}
}

func SetSSHPullOptions(worktree *git.Worktree) {
	err := worktree.Pull(&git.PullOptions{RemoteName: "origin", Auth: SetSSHConfig()})
	if err != nil {
		jsonLogger.Debug("Raven gitPush:Pull error", "error", err)
	}
}

func SetPullOptions(cfg config.Config, worktree *git.Worktree) {
	if strings.HasPrefix(cfg.RepoUrl, "ssh:") {
		SetSSHPullOptions(worktree)
	} else if strings.HasPrefix(cfg.RepoUrl, "http") {
		SetHTTPSPullOptions(worktree)
	}
}

func SetPushOptions(cfg config.Config, repository *git.Repository, commit plumbing.Hash) {
	if strings.HasPrefix(cfg.RepoUrl, "ssh:") {
		SetSSHPushOptions(cfg, repository)
	} else if strings.HasPrefix(cfg.RepoUrl, "http") {
		SetHTTPSPushOptions(repository, commit)
	}
}

func SetSSHCloneOptions(cfg config.Config) *git.CloneOptions {
	return &git.CloneOptions{
		URL:  cfg.RepoUrl,
		Auth: SetSSHConfig(),
	}
}

func SetHTTPSCloneOptions(cfg config.Config) *git.CloneOptions {
	return &git.CloneOptions{
		URL: cfg.RepoUrl,
	}
}

func SetCloneOptions(cfg config.Config) *git.CloneOptions {
	if strings.HasPrefix(cfg.RepoUrl, "https://") {
		return SetHTTPSCloneOptions(cfg)
	} else if strings.HasPrefix(cfg.RepoUrl, "ssh://") {
		return SetSSHCloneOptions(cfg)
	}
	jsonLogger.Error("Raven could not determine clone options", "config.RepoUrl", cfg.RepoUrl)
	helpers.WriteErrorToTerminationLog(fmt.Sprintf("Raven could not determine clone options(%s)", cfg.RepoUrl))
	return nil
}

func PlainClone(cfg config.Config, options *git.CloneOptions) {
	remote, err := git.PlainClone(cfg.ClonePath, false, options)
	if err != nil {
		jsonLogger.Debug("Raven GitClone error", "error", err)
	} else {
		head, err := remote.Head()
		if err != nil {
			jsonLogger.Warn("Gitclone Remote.head()", "head", head, "error", err)
		}
	}
	jsonLogger.Info("Raven successfully cloned repository", "repo", cfg.RepoUrl)
}

func RemoveFromWorkingtree(RipeSecrets []string, worktree *git.Worktree, cfg config.Config) {
	for ripe := range RipeSecrets {
		base := filepath.Join("declarative", cfg.DestEnv, "sealedsecrets")
		newbase := base + "/" + RipeSecrets[ripe] + ".yaml"
		_, err := worktree.Remove(newbase)
		if err != nil {
			jsonLogger.Error("removeFromWorktree remove failed", "err", err)
		}
		jsonLogger.Info("HarvestRipeSecrets found ripe secret. marked for deletion", "absolutePath", newbase, "ripeSecret", RipeSecrets[ripe], "action", "delete")
	}
}

func GetBaseListOfFiles(cfg config.Config) ([]fs.FileInfo, error) {
	base := filepath.Join(cfg.ClonePath, "declarative", cfg.DestEnv, "sealedsecrets")
	files, err := ioutil.ReadDir(base)
	if err != nil {
		jsonLogger.Error("ioutil.ReadDir() error", "error", err)
	}
	return files, err
}

func RemoveFileFromWorktree(path string, worktree *git.Worktree) {
	_, err := worktree.Remove(path)
	if err != nil {
		jsonLogger.Error("removeFromWorktree remove failed", "err", err)
	}
}

func RemoveFilesFromWorkTree(files []fs.FileInfo, worktree *git.Worktree, cfg config.Config) *git.Worktree {
	for _, f := range files {
		absolutePath := helpers.MakeAbsolutePath(cfg.DestEnv, f)
		RemoveFileFromWorktree(absolutePath, worktree)
		jsonLogger.Info("HarvestRipeSecrets found ripe secret. marked for deletion", "absolutePath", absolutePath, "ripeSecret", f.Name(), "action", "delete")
	}
	return worktree
}

func CleanDeadEntries(cfg config.Config) {
	jsonLogger.Info("list is nil. We should check if we have a directory full of files that should be deleted from git.")
	repository := InitializeGitRepo(cfg)
	worktree := InitializeWorkTree(repository)
	files, _ := GetBaseListOfFiles(cfg)

	if len(files) > 0 {
		RemoveFilesFromWorkTree(files, worktree, cfg)
		status, _ := GetGitStatus(worktree)

		if !status.IsClean() {
			jsonLogger.Debug("HarvestRipeSecret !status.IsClean()", "worktree", worktree, "status", status)
			commit, _ := MakeCommit(worktree, "Raven Removed ripe secret(s) from git", cfg.DestEnv)
			SetPushOptions(cfg, repository, commit)
		}
	}
	jsonLogger.Info("Going to sleep now.")
	time.Sleep(30 * time.Second)
}
