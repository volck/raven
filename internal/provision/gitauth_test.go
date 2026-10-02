package provision

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	cryptossh "golang.org/x/crypto/ssh"
)

// writeKeyPair writes an ed25519 private key and a known_hosts entry for
// host, returning both paths.
func writeKeyPair(t *testing.T, host string) (keyPath, knownHostsPath string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	block, err := cryptossh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	dir := t.TempDir()
	keyPath = filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	sshPub, err := cryptossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh public key: %v", err)
	}
	knownHostsPath = filepath.Join(dir, "known_hosts")
	entry := fmt.Sprintf("%s %s", host, cryptossh.MarshalAuthorizedKey(sshPub))
	if err := os.WriteFile(knownHostsPath, []byte(entry), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	return keyPath, knownHostsPath
}

// C5: an ssh:// remote must never fall back to accepting any host key. This
// is a configuration-seam assertion; it cannot be exercised over file://.
func TestNewGitAuth(t *testing.T) {
	t.Parallel()

	keyPath, knownHostsPath := writeKeyPair(t, "git.example.com")

	t.Run("ssh without host key verification is refused", func(t *testing.T) {
		t.Parallel()
		if _, err := NewGitAuth("ssh://git@git.example.com/sec/repo.git", keyPath, "", false); err == nil {
			t.Fatal("NewGitAuth() = nil error, want refusal to skip host key verification")
		}
	})

	t.Run("ssh with known_hosts verifies the host key", func(t *testing.T) {
		t.Parallel()
		auth, err := NewGitAuth("ssh://git@git.example.com/sec/repo.git", keyPath, knownHostsPath, false)
		if err != nil {
			t.Fatalf("NewGitAuth() error = %v", err)
		}
		keys, ok := auth.(*ssh.PublicKeys)
		if !ok {
			t.Fatalf("auth is %T, want *ssh.PublicKeys", auth)
		}
		if keys.HostKeyCallback == nil {
			t.Fatal("HostKeyCallback is nil, want host key verification")
		}
	})

	t.Run("insecure is an explicit opt-in", func(t *testing.T) {
		t.Parallel()
		if _, err := NewGitAuth("ssh://git@git.example.com/sec/repo.git", keyPath, "", true); err != nil {
			t.Fatalf("NewGitAuth() error = %v", err)
		}
	})

	t.Run("local remote needs no auth", func(t *testing.T) {
		t.Parallel()
		auth, err := NewGitAuth("file:///srv/git/repo.git", "", "", false)
		if err != nil {
			t.Fatalf("NewGitAuth() error = %v", err)
		}
		if auth != nil {
			t.Fatalf("auth = %v, want nil for file:// remote", auth)
		}
	})
}
