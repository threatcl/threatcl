package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// deriveAPIBaseURLFromTarget maps a threatcl cloud web target (e.g.
// "beta.threatcl.com") to its API base URL (e.g.
// "https://beta-api.threatcl.com").
//
// Mapping rules for the hostname:
//   - a first label of "api" or ending in "-api" is used unchanged
//   - hosts with a subdomain get "-api" appended to the first label:
//     beta.threatcl.com -> beta-api.threatcl.com
//   - apex domains get an "api." prefix: threatcl.com -> api.threatcl.com
//   - single-label hosts (localhost) and IP addresses are used unchanged
//
// The scheme defaults to https when the target doesn't specify one, and any
// port is preserved. Targets the mapping can't derive should use -api-url
// instead.
func deriveAPIBaseURLFromTarget(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("target cannot be empty")
	}

	if !strings.Contains(target, "://") {
		target = "https://" + target
	}

	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("invalid target %q: %w", target, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported target scheme %q", u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("could not determine host from target %q", target)
	}

	apiHost := mapTargetHostToAPIHost(host)
	if port := u.Port(); port != "" {
		apiHost = net.JoinHostPort(apiHost, port)
	} else if strings.Contains(apiHost, ":") {
		// bare IPv6 host needs brackets to form a valid URL
		apiHost = "[" + apiHost + "]"
	}

	return fmt.Sprintf("%s://%s", u.Scheme, apiHost), nil
}

// mapTargetHostToAPIHost applies the hostname mapping rules described on
// deriveAPIBaseURLFromTarget.
func mapTargetHostToAPIHost(host string) string {
	// IP addresses and single-label hosts (localhost etc.) pass through
	if net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return host
	}

	labels := strings.Split(host, ".")

	// Already an API host: api.threatcl.com or beta-api.threatcl.com
	if labels[0] == "api" || strings.HasSuffix(labels[0], "-api") {
		return host
	}

	// Apex domain: threatcl.com -> api.threatcl.com
	if len(labels) == 2 {
		return "api." + host
	}

	// Subdomain: beta.threatcl.com -> beta-api.threatcl.com
	labels[0] += "-api"
	return strings.Join(labels, ".")
}

// resolveLoginAPIBaseURL resolves the API endpoint for commands that mint or
// store tokens (login, token add). Precedence: -api-url flag, -target flag
// (mapped to an API host), THREATCL_API_URL env var, then the default.
// Setting both flags is an error.
func resolveLoginAPIBaseURL(flagAPIURL, flagTarget string, fsSvc FileSystemService) (string, error) {
	if flagAPIURL != "" && flagTarget != "" {
		return "", fmt.Errorf("cannot set both -api-url and -target")
	}

	if flagAPIURL != "" {
		apiURL := strings.TrimSpace(flagAPIURL)
		if !strings.Contains(apiURL, "://") {
			apiURL = "https://" + apiURL
		}
		return strings.TrimSuffix(apiURL, "/"), nil
	}

	if flagTarget != "" {
		return deriveAPIBaseURLFromTarget(flagTarget)
	}

	return getAPIBaseURL(fsSvc), nil
}
