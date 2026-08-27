package flock

import (
	"fmt"
	"net/url"
)

// ValidateProxyURL checks that s is a syntactically valid http(s) URL with a
// host and no embedded credentials. RFC1918 / loopback hosts are allowed
// because flock typically runs inside an OpenShift cluster where targets are
// reachable only via private IPs.
//
// It returns nil if s is acceptable for use as a probe target base URL.
func ValidateProxyURL(s string) error {
	if s == "" {
		return fmt.Errorf("empty url")
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme %q not allowed (want http or https)", u.Scheme)
	}
	if u.Opaque != "" {
		return fmt.Errorf("opaque urls not allowed")
	}
	if u.Host == "" {
		return fmt.Errorf("url must include host")
	}
	if u.User != nil {
		return fmt.Errorf("url must not embed user info")
	}
	return nil
}
