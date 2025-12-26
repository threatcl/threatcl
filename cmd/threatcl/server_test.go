package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
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

	// Wait for server to be ready with retry logic
	var resp *http.Response
	var err error
	maxRetries := 300 // 30 retries * 100ms = 30 seconds max
	client := &http.Client{Timeout: 1 * time.Second}

	for range maxRetries {
		resp, err = client.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if err != nil {
		t.Fatalf("Failed to connect to server after %d retries: %s", maxRetries, err)
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
	graphqlReq := strings.NewReader(`{"query": "{ stats { totalThreatModels } }"}`)
	resp, err = client.Post(
		fmt.Sprintf("http://127.0.0.1:%d/graphql", port),
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

func TestServerFileWatcherSetup(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "watcher-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %s", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test HCL file
	testFile := filepath.Join(tmpDir, "test.hcl")
	testContent := `threatmodel "Test Model" {
		author = "Test Author"
	}`
	if err := os.WriteFile(testFile, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %s", err)
	}

	cmd := testServerCommand(t)
	cfg, _ := spec.LoadSpecConfig()
	tmCache := cache.NewThreatModelCache(cfg, tmpDir)
	err = tmCache.LoadAll()
	if err != nil {
		t.Fatalf("Failed to load cache: %s", err)
	}

	// Setup file watcher
	watcher, err := cmd.setupFileWatcher(tmCache, tmpDir)
	if err != nil {
		t.Fatalf("Failed to setup file watcher: %s", err)
	}
	defer watcher.Close()

	if watcher == nil {
		t.Fatal("Expected watcher to be created")
	}

	t.Log("File watcher setup successfully")
}

func TestServerFileWatcherModify(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping file watcher test in short mode")
	}

	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "watcher-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %s", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create initial test HCL file
	testFile := filepath.Join(tmpDir, "test.hcl")
	initialContent := `threatmodel "Test Model" {
		author = "Initial Author"
	}`
	if err := os.WriteFile(testFile, []byte(initialContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %s", err)
	}

	cmd := testServerCommand(t)
	cfg, _ := spec.LoadSpecConfig()
	tmCache := cache.NewThreatModelCache(cfg, tmpDir)
	err = tmCache.LoadAll()
	if err != nil {
		t.Fatalf("Failed to load cache: %s", err)
	}

	initialCount := tmCache.Count()
	if initialCount != 1 {
		t.Fatalf("Expected initial count of 1, got: %d", initialCount)
	}

	// Setup file watcher
	watcher, err := cmd.setupFileWatcher(tmCache, tmpDir)
	if err != nil {
		t.Fatalf("Failed to setup file watcher: %s", err)
	}
	defer watcher.Close()

	// Give watcher time to start
	time.Sleep(100 * time.Millisecond)

	// Modify the file
	modifiedContent := `threatmodel "Test Model" {
		author = "Modified Author"
	}`
	if err := os.WriteFile(testFile, []byte(modifiedContent), 0644); err != nil {
		t.Fatalf("Failed to modify test file: %s", err)
	}

	// Give watcher time to process the change
	time.Sleep(500 * time.Millisecond)

	// Count should remain the same (still 1 model)
	newCount := tmCache.Count()
	if newCount != 1 {
		t.Errorf("Expected count to remain 1 after modification, got: %d", newCount)
	}

	// Verify the model was reloaded with new content
	model, err := tmCache.Get("Test Model")
	if err != nil {
		t.Fatalf("Failed to get reloaded model: %s", err)
	}

	if model.Author != "Modified Author" {
		t.Errorf("Expected author to be 'Modified Author', got: %s", model.Author)
	}

	t.Log("File modification detected and reloaded successfully")
}

func TestServerFileWatcherCreate(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping file watcher test in short mode")
	}

	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "watcher-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %s", err)
	}
	defer os.RemoveAll(tmpDir)

	cmd := testServerCommand(t)
	cfg, _ := spec.LoadSpecConfig()
	tmCache := cache.NewThreatModelCache(cfg, tmpDir)
	err = tmCache.LoadAll()
	if err != nil {
		t.Fatalf("Failed to load cache: %s", err)
	}

	initialCount := tmCache.Count()
	if initialCount != 0 {
		t.Fatalf("Expected initial count of 0, got: %d", initialCount)
	}

	// Setup file watcher
	watcher, err := cmd.setupFileWatcher(tmCache, tmpDir)
	if err != nil {
		t.Fatalf("Failed to setup file watcher: %s", err)
	}
	defer watcher.Close()

	// Give watcher time to start
	time.Sleep(100 * time.Millisecond)

	// Create a new file
	newFile := filepath.Join(tmpDir, "new-model.hcl")
	newContent := `threatmodel "New Model" {
		author = "New Author"
	}`
	if err := os.WriteFile(newFile, []byte(newContent), 0644); err != nil {
		t.Fatalf("Failed to create new file: %s", err)
	}

	// Give watcher time to process the change
	time.Sleep(500 * time.Millisecond)

	// Count should increase to 1
	newCount := tmCache.Count()
	if newCount != 1 {
		t.Errorf("Expected count to be 1 after file creation, got: %d", newCount)
	}

	// Verify the model was loaded
	model, err := tmCache.Get("New Model")
	if err != nil {
		t.Fatalf("Failed to get new model: %s", err)
	}

	if model.Author != "New Author" {
		t.Errorf("Expected author to be 'New Author', got: %s", model.Author)
	}

	t.Log("File creation detected and loaded successfully")
}

func TestServerFileWatcherDelete(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping file watcher test in short mode")
	}

	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "watcher-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %s", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create initial test HCL file
	testFile := filepath.Join(tmpDir, "test.hcl")
	testContent := `threatmodel "Test Model" {
		author = "Test Author"
	}`
	if err := os.WriteFile(testFile, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %s", err)
	}

	cmd := testServerCommand(t)
	cfg, _ := spec.LoadSpecConfig()
	tmCache := cache.NewThreatModelCache(cfg, tmpDir)
	err = tmCache.LoadAll()
	if err != nil {
		t.Fatalf("Failed to load cache: %s", err)
	}

	initialCount := tmCache.Count()
	if initialCount != 1 {
		t.Fatalf("Expected initial count of 1, got: %d", initialCount)
	}

	// Setup file watcher
	watcher, err := cmd.setupFileWatcher(tmCache, tmpDir)
	if err != nil {
		t.Fatalf("Failed to setup file watcher: %s", err)
	}
	defer watcher.Close()

	// Give watcher time to start
	time.Sleep(100 * time.Millisecond)

	// Delete the file
	if err := os.Remove(testFile); err != nil {
		t.Fatalf("Failed to delete test file: %s", err)
	}

	// Give watcher time to process the change
	time.Sleep(500 * time.Millisecond)

	// Count should decrease to 0
	newCount := tmCache.Count()
	if newCount != 0 {
		t.Errorf("Expected count to be 0 after file deletion, got: %d", newCount)
	}

	// Verify the model was removed
	_, err = tmCache.Get("Test Model")
	if err == nil {
		t.Error("Expected error when getting deleted model, got nil")
	}

	t.Log("File deletion detected and removed from cache successfully")
}

func TestServerFileWatcherNonThreatModelFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping file watcher test in short mode")
	}

	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "watcher-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %s", err)
	}
	defer os.RemoveAll(tmpDir)

	cmd := testServerCommand(t)
	cfg, _ := spec.LoadSpecConfig()
	tmCache := cache.NewThreatModelCache(cfg, tmpDir)
	err = tmCache.LoadAll()
	if err != nil {
		t.Fatalf("Failed to load cache: %s", err)
	}

	// Setup file watcher
	watcher, err := cmd.setupFileWatcher(tmCache, tmpDir)
	if err != nil {
		t.Fatalf("Failed to setup file watcher: %s", err)
	}
	defer watcher.Close()

	// Give watcher time to start
	time.Sleep(100 * time.Millisecond)

	// Create a non-threat-model file (should be ignored)
	txtFile := filepath.Join(tmpDir, "readme.txt")
	if err := os.WriteFile(txtFile, []byte("Some text"), 0644); err != nil {
		t.Fatalf("Failed to create txt file: %s", err)
	}

	// Give watcher time to process
	time.Sleep(500 * time.Millisecond)

	// Count should remain 0 (txt files should be ignored)
	count := tmCache.Count()
	if count != 0 {
		t.Errorf("Expected count to remain 0 after creating txt file, got: %d", count)
	}

	t.Log("Non-threat-model files correctly ignored by watcher")
}

func TestServerHelpNoLongerMentionsNotImplemented(t *testing.T) {
	cmd := testServerCommand(t)

	help := cmd.Help()

	if strings.Contains(help, "not yet implemented") {
		t.Error("Help text should not mention 'not yet implemented' for -watch flag")
	}

	if strings.Contains(help, "Not yet implemented") {
		t.Error("Help text should not mention 'Not yet implemented' for -watch flag")
	}

	if !strings.Contains(help, "-watch") {
		t.Error("Help text should still mention -watch flag")
	}
}
