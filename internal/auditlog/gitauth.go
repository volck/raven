package auditlog

import (
	"fmt"
	"os"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	cryptossh "golang.org/x/crypto/ssh"
)

// LoadGitAuth constructs the transport.AuthMethod that matches the
// GitSourceConfig. An empty SSHKeyPath yields a nil AuthMethod (suitable for
// file://, http://, or https:// URLs without credentials). When SSHKeyPath
// is set, the key is read and parsed eagerly so configuration errors
// surface at startup rather than at first poll.
func LoadGitAuth(cfg GitSourceConfig) (transport.AuthMethod, error) {
	if cfg.SSHKeyPath == "" {
		return nil, nil
	}

	keyBytes, err := os.ReadFile(cfg.SSHKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read SSH key %s: %w", cfg.SSHKeyPath, err)
	}
	auth, err := ssh.NewPublicKeys("git", keyBytes, "")
	if err != nil {
		return nil, fmt.Errorf("parse SSH key %s: %w", cfg.SSHKeyPath, err)
	}

	if cfg.InsecureSkipHostKey {
		auth.HostKeyCallback = cryptossh.InsecureIgnoreHostKey()
	} else if cfg.KnownHostsPath != "" {
		cb, err := knownHostsCallback(cfg.KnownHostsPath)
		if err != nil {
			return nil, fmt.Errorf("known_hosts %s: %w", cfg.KnownHostsPath, err)
		}
		auth.HostKeyCallback = cb
	}
	return auth, nil
}

func knownHostsCallback(path string) (cryptossh.HostKeyCallback, error) {
	// Defer to go-git's ssh helper, which reads the file at call time.
	// Use a thin wrapper so the error path is testable.
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	return ssh.NewKnownHostsCallback(path)
}
