package main

import "testing"

func Test_isDocumentationKey(t *testing.T) {
	type args struct {
		DocumentationKeys []string
		key               string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDocumentationKey(tt.args.DocumentationKeys, tt.args.key); got != tt.want {
				t.Errorf("isDocumentationKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
