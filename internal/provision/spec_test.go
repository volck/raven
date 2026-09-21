package provision

import "testing"

// SecretEngine deliberately differs from DestEnv: the two are independent and
// a fixture where they match hides code that reaches for the wrong one.
func validSpec() RavenSpec {
	return RavenSpec{
		Name:         "ssg-dev",
		Namespace:    "ssg",
		SecretEngine: "kv",
		DestEnv:      "dev",
		RepoURL:      "ssh://git@bitbucket.example.com:7999/sec/sealedsecrets-dev.git",
		Image:        "registry.example.com/ssg/raven@sha256:abc",
		RouteHost:    "ssg-dev-ssg.apps.example.com",
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*RavenSpec)
		wantErr bool
	}{
		{name: "valid", mutate: func(*RavenSpec) {}},
		{name: "route host optional", mutate: func(s *RavenSpec) { s.RouteHost = "" }},

		{name: "empty name", mutate: func(s *RavenSpec) { s.Name = "" }, wantErr: true},
		{name: "uppercase name", mutate: func(s *RavenSpec) { s.Name = "SSG-Dev" }, wantErr: true},
		{name: "underscore name", mutate: func(s *RavenSpec) { s.Name = "ssg_dev" }, wantErr: true},
		{name: "name leading dash", mutate: func(s *RavenSpec) { s.Name = "-ssg" }, wantErr: true},

		{name: "empty namespace", mutate: func(s *RavenSpec) { s.Namespace = "" }, wantErr: true},
		{name: "invalid namespace", mutate: func(s *RavenSpec) { s.Namespace = "Ssg/Dev" }, wantErr: true},

		{name: "empty engine", mutate: func(s *RavenSpec) { s.SecretEngine = "" }, wantErr: true},
		{name: "engine with slash", mutate: func(s *RavenSpec) { s.SecretEngine = "kv/dev" }, wantErr: true},

		{name: "empty destEnv", mutate: func(s *RavenSpec) { s.DestEnv = "" }, wantErr: true},
		// DestEnv becomes a namespace and a git path segment, so it must not
		// be able to walk out of declarative/.
		{name: "destEnv escapes its directory", mutate: func(s *RavenSpec) { s.DestEnv = "../../etc" }, wantErr: true},

		{name: "empty repo url", mutate: func(s *RavenSpec) { s.RepoURL = "" }, wantErr: true},
		{name: "repo url with space", mutate: func(s *RavenSpec) { s.RepoURL = "ssh://git@x/a b.git" }, wantErr: true},

		{name: "empty image", mutate: func(s *RavenSpec) { s.Image = "" }, wantErr: true},
		{name: "image with space", mutate: func(s *RavenSpec) { s.Image = "registry / raven" }, wantErr: true},

		{name: "invalid route host", mutate: func(s *RavenSpec) { s.RouteHost = "not a host" }, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			spec := validSpec()
			tt.mutate(&spec)
			err := spec.Validate()
			if tt.wantErr && err == nil {
				t.Fatalf("Validate() = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}
