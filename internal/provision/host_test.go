package provision

import "testing"

func TestDefaultRouteHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		host          string
		clusterDomain string
		want          string
	}{
		{
			name:          "derives from name and namespace",
			clusterDomain: "apps.ocpdq02.example.com",
			want:          "ssg-dev-ssg.apps.ocpdq02.example.com",
		},
		{
			name:          "explicit host wins",
			host:          "custom.example.com",
			clusterDomain: "apps.ocpdq02.example.com",
			want:          "custom.example.com",
		},
		{
			name:          "no cluster domain leaves host empty",
			clusterDomain: "",
			want:          "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			spec := validSpec()
			spec.RouteHost = tt.host
			if got := spec.DefaultRouteHost(tt.clusterDomain); got != tt.want {
				t.Fatalf("DefaultRouteHost() = %q, want %q", got, tt.want)
			}
		})
	}
}
