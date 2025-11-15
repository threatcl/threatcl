package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/threatcl/spec"
	"github.com/threatcl/threatcl/internal/cache"
	"github.com/zenizh/go-capturer"
)

func testServerCommand(tb testing.TB) *ServerCommand {
	tb.Helper()

	d, err := os.MkdirTemp("", "")
	if err != nil {
		tb.Fatalf("Error creating tmp dir: %s", err)
	}

	_ = os.Setenv("HOME", d)

	cfg, _ := spec.LoadSpecConfig()

	tb.Cleanup(func() {
		os.RemoveAll(d)
	})

	global := &GlobalCmdOptions{}

	return &ServerCommand{
		GlobalCmdOptions: global,
		specCfg:          cfg,
	}
}

func TestServerRunEmpty(t *testing.T) {
	cmd := testServerCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{})
	})

	if code != 1 {
		t.Errorf("Expected code 1, got: %d", code)
	}

	if !strings.Contains(out, "Error: -dir flag is required") {
		t.Errorf("Expected output to contain 'Error: -dir flag is required', got: %s", out)
	}
}

func TestServerRunNonExistentDir(t *testing.T) {
	cmd := testServerCommand(t)

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{"-dir", "/nonexistent/path/that/does/not/exist"})
	})

	if code != 1 {
		t.Errorf("Expected code 1, got: %d", code)
	}

	if !strings.Contains(out, "does not exist") {
		t.Errorf("Expected output to contain 'does not exist', got: %s", out)
	}
}

func TestServerRunWithFile(t *testing.T) {
	cmd := testServerCommand(t)

	// Create a temp file (not a directory)
	tmpfile, err := os.CreateTemp("", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	var code int

	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{"-dir", tmpfile.Name()})
	})

	if code != 1 {
		t.Errorf("Expected code 1, got: %d", code)
	}

	if !strings.Contains(out, "is not a directory") {
		t.Errorf("Expected output to contain 'is not a directory', got: %s", out)
	}
}

func TestServerSetup(t *testing.T) {
	cmd := testServerCommand(t)

	// Use the examples directory
	examplesDir := "../../examples"
	if _, err := os.Stat(examplesDir); os.IsNotExist(err) {
		t.Skip("Examples directory not found, skipping test")
	}

	// Test that setupServer creates a valid server
	// We don't actually start it, just test the setup
	cfg, _ := spec.LoadSpecConfig()
	tmCache := cache.NewThreatModelCache(cfg, examplesDir)

	srv := cmd.setupServer(tmCache, 18081)

	if srv == nil {
		t.Fatal("Expected server to be created")
	}

	if srv.Addr != ":18081" {
		t.Errorf("Expected server addr ':18081', got: %s", srv.Addr)
	}
}

func TestServerIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Use the examples directory
	examplesDir := "../../examples"
	if _, err := os.Stat(examplesDir); os.IsNotExist(err) {
		t.Skip("Examples directory not found, skipping test")
	}

	cmd := testServerCommand(t)

	// Use a unique port to avoid conflicts
	port := 18082

	// Start server in a goroutine
	done := make(chan int)
	go func() {
		code := cmd.Run([]string{"-dir", examplesDir, "-port", fmt.Sprintf("%d", port)})
		done <- code
	}()

	// Give server time to start
	time.Sleep(2 * time.Second)

	// Test health endpoint
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/health", port))
	if err != nil {
		t.Fatalf("Failed to connect to server: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got: %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "threat models loaded") {
		t.Errorf("Expected health response to contain 'threat models loaded', got: %s", string(body))
	}

	// Test GraphQL endpoint with a simple query
	client := &http.Client{Timeout: 5 * time.Second}
	graphqlReq := strings.NewReader(`{"query": "{ stats { totalThreatModels } }"}`)
	resp, err = client.Post(
		fmt.Sprintf("http://localhost:%d/graphql", port),
		"application/json",
		graphqlReq,
	)
	if err != nil {
		t.Fatalf("Failed to query GraphQL endpoint: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected GraphQL status 200, got: %d", resp.StatusCode)
	}

	body, _ = io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "totalThreatModels") {
		t.Errorf("Expected GraphQL response to contain 'totalThreatModels', got: %s", string(body))
	}

	// Shutdown server gracefully
	// Send interrupt to the running process
	// Note: In a real scenario, we'd send SIGINT, but for testing we can just verify it started
	t.Log("Server started and responded successfully")
}

func TestServerHelp(t *testing.T) {
	cmd := testServerCommand(t)

	help := cmd.Help()

	expectedStrings := []string{
		"Usage: threatcl server",
		"-dir=<path>",
		"-port=<number>",
		"-watch",
		"GraphQL API server",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(help, expected) {
			t.Errorf("Expected help to contain '%s', got: %s", expected, help)
		}
	}
}

func TestServerSynopsis(t *testing.T) {
	cmd := testServerCommand(t)

	synopsis := cmd.Synopsis()

	if synopsis == "" {
		t.Error("Expected non-empty synopsis")
	}

	if !strings.Contains(synopsis, "GraphQL") {
		t.Errorf("Expected synopsis to mention GraphQL, got: %s", synopsis)
	}
}

