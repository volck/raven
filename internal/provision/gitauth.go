package provision

import (
	"fmt"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/volck/raven/internal/auditlog"
)

// NewGitAuth builds the auth method for the GitOps remote. For ssh:// remotes
// it insists on host key verification: skipping it must be a deliberate
// choice, never the consequence of an unset variable.
func NewGitAuth(repoURL, sshKeyPath, knownHostsPath string, insecureSkipHostKey bool) (transport.AuthMethod, error) {
	if isSSH(repoURL) {
		if sshKeyPath == "" {
			return nil, fmt.Errorf("ssh remote %s: ssh key path is required", repoURL)
		}
		if knownHostsPath == "" && !insecureSkipHostKey {
			return nil, fmt.Errorf("ssh remote %s: known_hosts path is required unless host key verification is explicitly disabled", repoURL)
		}
	}
	return auditlog.LoadGitAuth(auditlog.GitSourceConfig{
		URL:                 repoURL,
		SSHKeyPath:          sshKeyPath,
		KnownHostsPath:      knownHostsPath,
		InsecureSkipHostKey: insecureSkipHostKey,
	})
}

func isSSH(repoURL string) bool {
	return strings.HasPrefix(repoURL, "ssh://") ||
		(!strings.Contains(repoURL, "://") && strings.Contains(repoURL, "@"))
}
