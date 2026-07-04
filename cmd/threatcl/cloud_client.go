package main

import (
	"fmt"
	"net/url"
)

// CloudClient is the deep module for talking to the threatcl cloud API. It
// captures the auth token, the active organization, the API base URL and the
// HTTP transport once at construction so callers no longer thread
// (token, orgId, httpClient, fsSvc) through every API call. Every cloud API
// method hangs off this type; command code holds a *CloudClient and calls verbs
// like client.FetchThreatModels().
type CloudClient struct {
	token   string
	orgId   string
	baseURL string
	http    HTTPClient
}

// NewCloudClient builds a CloudClient bound to a token, organization and API
// base URL over the given transport.
func NewCloudClient(token, orgId, baseURL string, httpClient HTTPClient) *CloudClient {
	return &CloudClient{
		token:   token,
		orgId:   orgId,
		baseURL: baseURL,
		http:    httpClient,
	}
}

// OrgID returns the organization the client is currently scoped to.
func (c *CloudClient) OrgID() string {
	return c.orgId
}

// WithOrg returns a shallow copy of the client scoped to a different
// organization, sharing the same token, base URL and transport. It is used when
// an operation resolves the org dynamically (e.g. from a threat model's backend
// block) rather than from the construction-time org.
func (c *CloudClient) WithOrg(orgId string) *CloudClient {
	clone := *c
	clone.orgId = orgId
	return &clone
}

// DownloadModelURL returns the API URL for downloading a threat model's current
// spec file. Exposed so download commands can hand it to downloadToFile.
func (c *CloudClient) DownloadModelURL(modelIdOrSlug string) string {
	return fmt.Sprintf("%s/api/v1/org/%s/models/%s/download",
		c.baseURL, url.PathEscape(c.orgId), url.PathEscape(modelIdOrSlug))
}

// DownloadModelVersionURL returns the API URL for downloading a specific version
// of a threat model's spec file.
func (c *CloudClient) DownloadModelVersionURL(modelIdOrSlug, version string) string {
	return fmt.Sprintf("%s/api/v1/org/%s/models/%s/versions/%s/download",
		c.baseURL, url.PathEscape(c.orgId), url.PathEscape(modelIdOrSlug), url.PathEscape(version))
}
