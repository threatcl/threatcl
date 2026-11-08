package main

import (
	"net/http"
	"time"

	"github.com/threatcl/threatcl/version"
)

// cloudUserAgent is the User-Agent sent on every Threatcl Cloud API request.
// Threatcl Cloud classifies API-token requests whose User-Agent starts with
// "threatcl/" as coming from the CLI, so the prefix must stay exactly this.
func cloudUserAgent() string {
	return "threatcl/" + version.Version
}

// userAgentTransport is an http.RoundTripper that stamps cloudUserAgent onto
// every outgoing request before handing it to base. Installing it on the
// shared client means individual call sites never need to set the header.
type userAgentTransport struct {
	base http.RoundTripper
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// RoundTrippers must not modify the caller's request, so set the header on
	// a clone.
	req = req.Clone(req.Context())
	req.Header.Set("User-Agent", cloudUserAgent())

	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

// newDefaultHTTPClient builds the HTTPClient used for Threatcl Cloud API
// calls: a plain http.Client with the given timeout whose transport sets the
// threatcl User-Agent.
func newDefaultHTTPClient(timeout time.Duration) *defaultHTTPClient {
	return &defaultHTTPClient{
		client: &http.Client{
			Timeout:   timeout,
			Transport: &userAgentTransport{},
		},
	}
}
