package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// recordingTransport is a self-contained HTTPClient that records every request
// (method, URL, headers, body) and returns a single configured response. It lets
// the CloudClient tests assert exactly what the client puts on the wire.
type recordingTransport struct {
	status int
	body   string
	err    error

	reqs   []*http.Request
	bodies []string
}

func (rt *recordingTransport) Do(req *http.Request) (*http.Response, error) {
	var b []byte
	if req.Body != nil {
		b, _ = io.ReadAll(req.Body)
	}
	rt.reqs = append(rt.reqs, req)
	rt.bodies = append(rt.bodies, string(b))
	if rt.err != nil {
		return nil, rt.err
	}
	resp := &http.Response{
		StatusCode: rt.status,
		Body:       io.NopCloser(strings.NewReader(rt.body)),
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")
	return resp, nil
}

func (rt *recordingTransport) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	req, _ := http.NewRequest("POST", url, body)
	req.Header.Set("Content-Type", contentType)
	return rt.Do(req)
}

func newTestClient(status int, body string) (*CloudClient, *recordingTransport) {
	rt := &recordingTransport{status: status, body: body}
	return NewCloudClient("tok-123", "org-abc", "https://api.test", rt), rt
}

func (rt *recordingTransport) last() *http.Request {
	if len(rt.reqs) == 0 {
		return nil
	}
	return rt.reqs[len(rt.reqs)-1]
}

// --- happy path: correct decode + exact request shape ---

func TestCloudClientFetchThreatModels(t *testing.T) {
	client, rt := newTestClient(http.StatusOK, `[{"id":"tm1","name":"One"},{"id":"tm2","name":"Two"}]`)

	tms, err := client.FetchThreatModels()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tms) != 2 || tms[0].ID != "tm1" || tms[1].Name != "Two" {
		t.Fatalf("unexpected decode: %+v", tms)
	}

	req := rt.last()
	if req.Method != "GET" {
		t.Errorf("method = %q, want GET", req.Method)
	}
	if got, want := req.URL.String(), "https://api.test/api/v1/org/org-abc/models"; got != want {
		t.Errorf("url = %q, want %q", got, want)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer tok-123" {
		t.Errorf("auth header = %q, want %q", got, "Bearer tok-123")
	}
}

func TestCloudClientFetchThreatModelURL(t *testing.T) {
	client, rt := newTestClient(http.StatusOK, `{"id":"tm1","slug":"my-model"}`)

	tm, err := client.FetchThreatModel("my-model")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tm.Slug != "my-model" {
		t.Errorf("slug = %q", tm.Slug)
	}
	if got, want := rt.last().URL.String(), "https://api.test/api/v1/org/org-abc/models/my-model"; got != want {
		t.Errorf("url = %q, want %q", got, want)
	}
}

// --- PathEscape of org + path args ---

func TestCloudClientPathEscaping(t *testing.T) {
	rt := &recordingTransport{status: http.StatusOK, body: `{}`}
	client := NewCloudClient("tok", "org with space", "https://api.test", rt)

	_, _ = client.FetchThreatModel("a/b c")

	got := rt.last().URL.EscapedPath()
	if !strings.Contains(got, "org%20with%20space") {
		t.Errorf("org not escaped in %q", got)
	}
	if !strings.Contains(got, "a%2Fb%20c") {
		t.Errorf("model id not escaped in %q", got)
	}
}

// --- error mapping: 401 / custom-404 / generic 404 / 500 ---

func TestCloudClientUnauthorized(t *testing.T) {
	client, _ := newTestClient(http.StatusUnauthorized, `{"error":"nope"}`)
	_, err := client.FetchThreatModels()
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("want auth-failed error, got %v", err)
	}
}

func TestCloudClientCustomNotFound(t *testing.T) {
	client, _ := newTestClient(http.StatusNotFound, `{"error":"nope"}`)
	_, err := client.FetchThreatModel("ghost")
	if err == nil || !strings.Contains(err.Error(), "threat model not found: ghost") {
		t.Fatalf("want custom not-found, got %v", err)
	}
}

func TestCloudClientServerError(t *testing.T) {
	client, _ := newTestClient(http.StatusInternalServerError, `boom`)
	_, err := client.FetchThreatModels()
	if err == nil || !strings.Contains(err.Error(), "api returned status 500") {
		t.Fatalf("want status-500 error, got %v", err)
	}
}

func TestCloudClientTransportError(t *testing.T) {
	rt := &recordingTransport{err: io.ErrUnexpectedEOF}
	client := NewCloudClient("t", "o", "https://api.test", rt)
	_, err := client.FetchThreatModels()
	if err == nil {
		t.Fatal("want transport error, got nil")
	}
}

// --- WithOrg produces a re-scoped copy sharing token/baseURL ---

func TestCloudClientWithOrg(t *testing.T) {
	client, rt := newTestClient(http.StatusOK, `[]`)
	other := client.WithOrg("org-xyz")

	if other.OrgID() != "org-xyz" {
		t.Errorf("OrgID = %q, want org-xyz", other.OrgID())
	}
	if client.OrgID() != "org-abc" {
		t.Errorf("original org mutated: %q", client.OrgID())
	}

	_, _ = other.FetchThreatModels()
	req := rt.last()
	if got, want := req.URL.String(), "https://api.test/api/v1/org/org-xyz/models"; got != want {
		t.Errorf("url = %q, want %q", got, want)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer tok-123" {
		t.Errorf("token not shared with WithOrg copy: %q", got)
	}
}

// --- CreateThreatModel accepts 200 AND 201, sends name+description ---

func TestCloudClientCreateThreatModelAccepts201(t *testing.T) {
	client, rt := newTestClient(http.StatusCreated, `{"id":"tm1","name":"New"}`)

	tm, err := client.CreateThreatModel("New", "desc")
	if err != nil {
		t.Fatalf("201 should succeed, got %v", err)
	}
	if tm.Name != "New" {
		t.Errorf("name = %q", tm.Name)
	}
	body := rt.bodies[len(rt.bodies)-1]
	if !strings.Contains(body, `"name":"New"`) || !strings.Contains(body, `"description":"desc"`) {
		t.Errorf("payload = %q", body)
	}
}

func TestCloudClientCreateThreatModelAccepts200(t *testing.T) {
	client, _ := newTestClient(http.StatusOK, `{"id":"tm1","name":"New"}`)
	if _, err := client.CreateThreatModel("New", ""); err != nil {
		t.Fatalf("200 should succeed, got %v", err)
	}
}

// --- Upload sends multipart with the filename and content ---

func TestCloudClientUpload(t *testing.T) {
	client, rt := newTestClient(http.StatusOK, ``)

	err := client.Upload("my-model", "model.hcl", []byte("spec-bytes"), true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	req := rt.last()
	if got, want := req.URL.String(), "https://api.test/api/v1/org/org-abc/models/my-model/upload"; got != want {
		t.Errorf("url = %q, want %q", got, want)
	}
	if ct := req.Header.Get("Content-Type"); !strings.HasPrefix(ct, "multipart/form-data") {
		t.Errorf("content-type = %q, want multipart/form-data", ct)
	}
	body := rt.bodies[len(rt.bodies)-1]
	if !strings.Contains(body, "model.hcl") || !strings.Contains(body, "spec-bytes") {
		t.Errorf("multipart body missing filename/content: %q", body)
	}
	if !strings.Contains(body, "ignore-linked-controls") {
		t.Errorf("multipart body missing ignore-linked-controls field: %q", body)
	}
}

// --- EvaluatePolicies requires 201 exactly ---

func TestCloudClientEvaluatePolicies201(t *testing.T) {
	client, _ := newTestClient(http.StatusCreated, `{"id":"eval1","status":"completed"}`)
	eval, err := client.EvaluatePolicies("model-1")
	if err != nil {
		t.Fatalf("201 should succeed, got %v", err)
	}
	if eval.ID != "eval1" {
		t.Errorf("id = %q", eval.ID)
	}
}

func TestCloudClientEvaluatePolicies200IsError(t *testing.T) {
	client, _ := newTestClient(http.StatusOK, `{"id":"eval1"}`)
	if _, err := client.EvaluatePolicies("model-1"); err == nil {
		t.Fatal("200 (not 201) should be an error")
	}
}

// --- DeletePolicy expects 204 ---

func TestCloudClientDeletePolicy(t *testing.T) {
	client, rt := newTestClient(http.StatusNoContent, ``)
	if err := client.DeletePolicy("pol-1"); err != nil {
		t.Fatalf("204 should succeed, got %v", err)
	}
	if rt.last().Method != "DELETE" {
		t.Errorf("method = %q, want DELETE", rt.last().Method)
	}
}

// --- Validate*Refs: empty short-circuits (no HTTP), missing detection ---

func TestCloudClientValidateControlRefsEmpty(t *testing.T) {
	rt := &recordingTransport{err: io.ErrUnexpectedEOF} // would fail if called
	client := NewCloudClient("t", "o", "https://api.test", rt)

	found, missing, err := client.ValidateControlRefs(nil)
	if err != nil || found != nil || missing != nil {
		t.Fatalf("empty refs should short-circuit, got (%v,%v,%v)", found, missing, err)
	}
	if len(rt.reqs) != 0 {
		t.Errorf("expected no HTTP call, got %d", len(rt.reqs))
	}
}

func TestCloudClientValidateControlRefsMissing(t *testing.T) {
	client, _ := newTestClient(http.StatusOK,
		`{"data":{"controlLibraryItemsByRefs":[{"referenceId":"C1","name":"Found"}]}}`)

	found, missing, err := client.ValidateControlRefs([]string{"C1", "C2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := found["C1"]; !ok {
		t.Errorf("C1 should be found: %+v", found)
	}
	if len(missing) != 1 || missing[0] != "C2" {
		t.Errorf("missing = %v, want [C2]", missing)
	}
}

func TestCloudClientValidateControlRefsGraphQLError(t *testing.T) {
	client, _ := newTestClient(http.StatusOK, `{"errors":[{"message":"boom"}]}`)
	_, _, err := client.ValidateControlRefs([]string{"C1"})
	if err == nil || !strings.Contains(err.Error(), "GraphQL error") {
		t.Fatalf("want GraphQL error, got %v", err)
	}
}

// --- DownloadContent returns raw bytes on 200 ---

func TestCloudClientDownloadContent(t *testing.T) {
	client, _ := newTestClient(http.StatusOK, "raw-hcl-bytes")
	body, err := client.DownloadContent("https://api.test/api/v1/org/org-abc/models/m/download")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(body) != "raw-hcl-bytes" {
		t.Errorf("body = %q", string(body))
	}
}

// --- URL builders ---

func TestCloudClientDownloadURLBuilders(t *testing.T) {
	client := NewCloudClient("t", "org-abc", "https://api.test", &recordingTransport{})
	if got, want := client.DownloadModelURL("m"), "https://api.test/api/v1/org/org-abc/models/m/download"; got != want {
		t.Errorf("DownloadModelURL = %q, want %q", got, want)
	}
	if got, want := client.DownloadModelVersionURL("m", "1.2.0"), "https://api.test/api/v1/org/org-abc/models/m/versions/1.2.0/download"; got != want {
		t.Errorf("DownloadModelVersionURL = %q, want %q", got, want)
	}
}
