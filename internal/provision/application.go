package provision

import (
	"bytes"
	"embed"
	"fmt"
	"text/template"
)

//go:embed templates/application.yaml.tmpl
var templateFS embed.FS

var applicationTmpl = template.Must(template.ParseFS(templateFS, "templates/application.yaml.tmpl"))

// AppName is the Application's name. Fixed rather than derived: Applications
// are namespaced per tenant, so one name per namespace is unambiguous and
// matches the ones already in the repository.
const AppName = "sealed-secrets"

// ApplicationConfig describes the ArgoCD-side settings shared by every
// generated Application. The source repository and path are not here: they
// vary per raven and come from the RavenSpec.
type ApplicationConfig struct {
	TargetRevision string
	DestServer     string
}

// RenderApplication renders the ArgoCD Application for spec.
func RenderApplication(spec RavenSpec, cfg ApplicationConfig) ([]byte, error) {
	if err := spec.Validate(); err != nil {
		return nil, fmt.Errorf("validate spec: %w", err)
	}
	data := struct {
		Spec           RavenSpec
		Cfg            ApplicationConfig
		AppName        string
		Path           string
		LabelManagedBy string
		ManagedBy      string
	}{spec, cfg, AppName, spec.SealedSecretsPath(), LabelManagedBy, ManagedByWrangler}

	var buf bytes.Buffer
	if err := applicationTmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("render application: %w", err)
	}
	return buf.Bytes(), nil
}
