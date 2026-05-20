package api

import (
	"context"
	"os"
	"sync"

	"github.com/volck/raven/internal/argocd"
)

// argoClient is lazily constructed once per process from environment variables.
// It is safe to share: Client.RefreshAndSync is stateless beyond its config.
var (
	argoClientOnce sync.Once
	argoClient     *argocd.Client
)

func getArgoClient() *argocd.Client {
	argoClientOnce.Do(func() {
		argoClient = argocd.NewClient()
		if argoClient.Enabled() {
			jsonLogger.Info("argocd sync enabled",
				"server", argoClient.Server,
				"app", os.Getenv("ARGOCD_APP_NAME"))
		}
	})
	return argoClient
}

// defaultArgoSync is the default ArgoSync hook implementation. It reads the
// ArgoCD Application name from ARGOCD_APP_NAME and hard-refreshes + syncs it.
//
// The behaviour is a no-op (returns nil) when the ArgoCD client is not
// enabled (ARGOCD_SYNC_ENABLED!=true, missing ARGOCD_SERVER or
// ARGOCD_AUTH_TOKEN) or when ARGOCD_APP_NAME is empty.
//
// On success an "argocd-sync" event is recorded on the handler so the
// dashboard and event store reflect the operation. On error the event is
// recorded by the caller in handleCreateOrUpdate.
func (h *SecretEventHandler) defaultArgoSync(ctx context.Context, secretName string) error {
	c := getArgoClient()
	if !c.Enabled() {
		return nil
	}
	appName := os.Getenv("ARGOCD_APP_NAME")
	if appName == "" {
		jsonLogger.Warn("argocd sync skipped: ARGOCD_APP_NAME not set")
		return nil
	}
	if err := c.RefreshAndSync(ctx, appName); err != nil {
		return err
	}
	h.recordEvent("argocd-sync", h.cfg.SecretEngine, secretName, "ok", "app="+appName)
	return nil
}
