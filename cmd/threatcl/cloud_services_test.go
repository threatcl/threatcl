package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Tests for the default service implementations in cloud_services.go.
// defaultKeyringService is intentionally not covered: it opens the real OS
// keyring, which is neither deterministic nor safe to touch in unit tests.

func TestDefaultFileSystemService(t *testing.T) {
	svc := &defaultFileSystemService{}

	t.Run("write and read file roundtrip", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "roundtrip.txt")
		content := []byte("hello threatcl")

		if err := svc.WriteFile(path, content, 0644); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}

		got, err := svc.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile failed: %v", err)
		}

		if string(got) != string(content) {
			t.Errorf("expected content %q, got %q", content, got)
		}
	})

	t.Run("read missing file returns error", func(t *testing.T) {
		_, err := svc.ReadFile(filepath.Join(t.TempDir(), "does-not-exist.txt"))
		if err == nil {
			t.Fatal("expected error reading missing file, got nil")
		}
		if !os.IsNotExist(err) {
			t.Errorf("expected not-exist error, got %v", err)
		}
	})

	t.Run("mkdirall creates nested directories", func(t *testing.T) {
		nested := filepath.Join(t.TempDir(), "a", "b", "c")

		if err := svc.MkdirAll(nested, 0755); err != nil {
			t.Fatalf("MkdirAll failed: %v", err)
		}

		info, err := svc.Stat(nested)
		if err != nil {
			t.Fatalf("Stat failed: %v", err)
		}
		if !info.IsDir() {
			t.Errorf("expected %q to be a directory", nested)
		}
	})

	t.Run("stat file reports non-directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "file.txt")
		if err := svc.WriteFile(path, []byte("x"), 0644); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}

		info, err := svc.Stat(path)
		if err != nil {
			t.Fatalf("Stat failed: %v", err)
		}
		if info.IsDir() {
			t.Errorf("expected %q to be a file, reported as directory", path)
		}
		if info.Name() != "file.txt" {
			t.Errorf("expected name %q, got %q", "file.txt", info.Name())
		}
	})

	t.Run("stat missing path returns error", func(t *testing.T) {
		_, err := svc.Stat(filepath.Join(t.TempDir(), "missing"))
		if err == nil {
			t.Fatal("expected error for missing path, got nil")
		}
		if !os.IsNotExist(err) {
			t.Errorf("expected not-exist error, got %v", err)
		}
	})

	t.Run("getenv reads environment", func(t *testing.T) {
		t.Setenv("THREATCL_SERVICES_TEST_VAR", "test-value")

		if got := svc.Getenv("THREATCL_SERVICES_TEST_VAR"); got != "test-value" {
			t.Errorf("expected %q, got %q", "test-value", got)
		}

		if got := svc.Getenv("THREATCL_SERVICES_TEST_UNSET_VAR"); got != "" {
			t.Errorf("expected empty string for unset var, got %q", got)
		}
	})
}

func TestDefaultHTTPClient(t *testing.T) {
	// A local loopback test server keeps this deterministic with no external
	// network access.
	type receivedRequest struct {
		method      string
		path        string
		auth        string
		contentType string
		body        string
	}

	var received receivedRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = receivedRequest{
			method:      r.Method,
			path:        r.URL.Path,
			auth:        r.Header.Get("Authorization"),
			contentType: r.Header.Get("Content-Type"),
			body:        string(body),
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client := &defaultHTTPClient{
		client: &http.Client{Timeout: 5 * time.Second},
	}

	t.Run("Do sends request and returns response", func(t *testing.T) {
		req, err := http.NewRequest("GET", server.URL+"/api/v1/test", nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer test-token")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Do failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}
		if string(body) != `{"ok":true}` {
			t.Errorf("unexpected response body %q", body)
		}

		if received.method != "GET" {
			t.Errorf("expected GET, server saw %q", received.method)
		}
		if received.path != "/api/v1/test" {
			t.Errorf("expected path /api/v1/test, server saw %q", received.path)
		}
		if received.auth != "Bearer test-token" {
			t.Errorf("expected Authorization header to be forwarded, server saw %q", received.auth)
		}
	})

	t.Run("Post sends body with content type", func(t *testing.T) {
		resp, err := client.Post(server.URL+"/api/v1/post-test", "application/json", strings.NewReader(`{"key":"value"}`))
		if err != nil {
			t.Fatalf("Post failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}

		if received.method != "POST" {
			t.Errorf("expected POST, server saw %q", received.method)
		}
		if received.path != "/api/v1/post-test" {
			t.Errorf("expected path /api/v1/post-test, server saw %q", received.path)
		}
		if received.contentType != "application/json" {
			t.Errorf("expected content type application/json, server saw %q", received.contentType)
		}
		if received.body != `{"key":"value"}` {
			t.Errorf("expected body to be forwarded, server saw %q", received.body)
		}
	})

	t.Run("Do returns error for unreachable server", func(t *testing.T) {
		// Close a dedicated server to get a port that refuses connections.
		dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		deadURL := dead.URL
		dead.Close()

		req, err := http.NewRequest("GET", deadURL+"/api/v1/test", nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		if _, err := client.Do(req); err == nil {
			t.Error("expected error connecting to closed server, got nil")
		}
	})
}
