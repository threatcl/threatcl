package main

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/threatcl/threatcl/version"
)

// setTestVersion overrides version.Version for the duration of a test.
func setTestVersion(t *testing.T, v string) {
	t.Helper()
	orig := version.Version
	version.Version = v
	t.Cleanup(func() { version.Version = orig })
}

// capturedRequest is what userAgentServer records for each request it sees.
type capturedRequest struct {
	userAgent     string
	authorization string
}

// userAgentServer is an httptest server that records the headers of every
// request by path and replies 200 with the canned body for that path.
type userAgentServer struct {
	*httptest.Server
	mu   sync.Mutex
	seen map[string]capturedRequest
}

func newUserAgentServer(t *testing.T, bodies map[string]string) *userAgentServer {
	t.Helper()
	s := &userAgentServer{seen: make(map[string]capturedRequest)}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.seen[r.URL.Path] = capturedRequest{
			userAgent:     r.Header.Get("User-Agent"),
			authorization: r.Header.Get("Authorization"),
		}
		s.mu.Unlock()

		body, ok := bodies[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

// request returns the captured request for path, failing the test if the
// server never saw it.
func (s *userAgentServer) request(t *testing.T, path string) capturedRequest {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	got, ok := s.seen[path]
	if !ok {
		t.Fatalf("server never received a request for %s", path)
	}
	return got
}

func TestCloudUserAgent(t *testing.T) {
	for _, v := range []string{"1.2.3", "dev"} {
		setTestVersion(t, v)
		if got, want := cloudUserAgent(), "threatcl/"+v; got != want {
			t.Errorf("cloudUserAgent() with version %q = %q, want %q", v, got, want)
		}
	}
}

func TestCloudUserAgentAuthenticatedRequests(t *testing.T) {
	setTestVersion(t, "1.2.3")
	const wantUA = "threatcl/1.2.3"

	whoami := map[string]string{
		"/api/v1/users/me": `{"id":"user-1","organizations":[]}`,
	}

	t.Run("CloudClient via initDependencies", func(t *testing.T) {
		server := newUserAgentServer(t, whoami)

		// Use the production client construction path (cloud_base.go).
		httpClient, _, _ := (&CloudCommandBase{}).initDependencies(5 * time.Second)

		if _, err := NewCloudClient("test-token", "org-1", server.URL, httpClient).FetchUserInfo(); err != nil {
			t.Fatalf("FetchUserInfo failed: %v", err)
		}

		got := server.request(t, "/api/v1/users/me")
		if got.authorization != "Bearer test-token" {
			t.Errorf("Authorization = %q, want %q", got.authorization, "Bearer test-token")
		}
		if got.userAgent != wantUA {
			t.Errorf("User-Agent = %q, want %q", got.userAgent, wantUA)
		}
	})

	t.Run("validateToken default client", func(t *testing.T) {
		// A nil HTTPClient makes validateToken build its own (cloud_tokenstore.go).
		server := newUserAgentServer(t, whoami)
		fsSvc := newMockFileSystemService()
		fsSvc.setEnv("THREATCL_API_URL", server.URL)

		valid, err := validateToken("test-token", nil, fsSvc)
		if err != nil || !valid {
			t.Fatalf("validateToken = (%v, %v), want (true, nil)", valid, err)
		}

		if got := server.request(t, "/api/v1/users/me").userAgent; got != wantUA {
			t.Errorf("User-Agent = %q, want %q", got, wantUA)
		}
	})
}

func TestCloudUserAgentDeviceFlow(t *testing.T) {
	setTestVersion(t, "1.2.3")
	const wantUA = "threatcl/1.2.3"

	server := newUserAgentServer(t, map[string]string{
		"/api/v1/auth/device":      `{"device_code":"device-123","user_code":"ABCD-1234","verification_url":"https://example.test/device","expires_in":60,"interval":1}`,
		"/api/v1/auth/device/poll": `{"access_token":"access-123","token_type":"Bearer","organization_id":"org-1"}`,
	})

	cmd := &CloudLoginCommand{}
	// Same client construction as CloudLoginCommand.Run.
	httpClient, _, _ := cmd.initDependencies(5 * time.Second)

	deviceResp, err := cmd.requestDeviceCode(server.URL, httpClient)
	if err != nil {
		t.Fatalf("requestDeviceCode failed: %v", err)
	}
	if _, err := cmd.pollForToken(deviceResp, server.URL, httpClient); err != nil {
		t.Fatalf("pollForToken failed: %v", err)
	}

	for _, path := range []string{"/api/v1/auth/device", "/api/v1/auth/device/poll"} {
		if got := server.request(t, path).userAgent; got != wantUA {
			t.Errorf("%s User-Agent = %q, want %q", path, got, wantUA)
		}
	}
}

func TestUserAgentTransportDoesNotMutateRequest(t *testing.T) {
	server := newUserAgentServer(t, map[string]string{"/": `{}`})

	req, err := http.NewRequest("GET", server.URL+"/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := newDefaultHTTPClient(5 * time.Second).Do(req)
	if err != nil {
		t.Fatalf("Do failed: %v", err)
	}
	resp.Body.Close()

	if ua := req.Header.Get("User-Agent"); ua != "" {
		t.Errorf("caller's request was modified: User-Agent = %q", ua)
	}
	if got := server.request(t, "/").userAgent; got != cloudUserAgent() {
		t.Errorf("User-Agent = %q, want %q", got, cloudUserAgent())
	}
}
