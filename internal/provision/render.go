package provision

import "fmt"

// File is a single blob destined for the GitOps repository.
type File struct {
	Name string
	Data []byte
}

// Render returns everything that gets committed for spec. Deliberately just
// the ArgoCD Application: the raven's Deployment, Service, Route and Vault
// token are applied imperatively in-cluster and must never reach git.
func Render(spec RavenSpec, cfg ApplicationConfig) ([]File, error) {
	app, err := RenderApplication(spec, cfg)
	if err != nil {
		return nil, err
	}
	return []File{{
		Name: fmt.Sprintf("declarative/%s/infra/argocd/applications/%s.yaml", spec.DestEnv, AppName),
		Data: app,
	}}, nil
}
