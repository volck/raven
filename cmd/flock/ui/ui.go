// Package ui hosts the embedded templates and static assets for flock's
// reference web UI mounted at /. The package only exposes the embed.FS
// values and a small Renderer; routing/handlers live in cmd/flock so they
// can reach the existing Snapshotter interfaces directly.
package ui

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

// StaticFS returns the embedded static asset tree rooted at /static.
func StaticFS() fs.FS {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		// staticFS is a compile-time constant — this never fails in
		// practice but we surface it loudly if the layout drifts.
		panic(fmt.Errorf("ui: static sub fs: %w", err))
	}
	return sub
}

// Renderer parses every page template once and renders them by name.
type Renderer struct {
	tmpls map[string]*template.Template
}

// NewRenderer parses layout.html + every page template under templates/.
// Each page template defines a "content" block that layout.html invokes.
func NewRenderer() (*Renderer, error) {
	pages := []string{"dashboard.html", "engine.html", "secret.html"}
	out := map[string]*template.Template{}
	for _, p := range pages {
		t, err := template.ParseFS(templatesFS, "templates/layout.html", "templates/"+p)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		out[p] = t
	}
	return &Renderer{tmpls: out}, nil
}

// Render writes the named page (e.g. "dashboard.html") to w with data.
func (r *Renderer) Render(w io.Writer, name string, data any) error {
	t, ok := r.tmpls[name]
	if !ok {
		return fmt.Errorf("ui: unknown template %q", name)
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", data); err != nil {
		return fmt.Errorf("execute %s: %w", name, err)
	}
	_, err := w.Write(buf.Bytes())
	return err
}
