package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/threatcl/spec"
)

// Mock implementations for testing

// mockRoundTripper implements http.RoundTripper for mocking HTTP responses
type mockRoundTripper struct {
	mu         sync.Mutex
	responses  map[string]*http.Response
	errors     map[string]error
	callCounts map[string]int
}

func newMockRoundTripper() *mockRoundTripper {
	return &mockRoundTripper{
		responses:  make(map[string]*http.Response),
		errors:     make(map[string]error),
		callCounts: make(map[string]int),
	}
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s %s", req.Method, req.URL.Path)
	m.callCounts[key]++

	// Check for errors first
	if err, ok := m.errors[key]; ok {
		return nil, err
	}

	// Check for specific response
	if resp, ok := m.responses[key]; ok {
		return resp, nil
	}

	// Default 404 response
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(strings.NewReader(`{"error":"not found"}`)),
		Header:     make(http.Header),
	}, nil
}

// setResponse sets a mock response for a given method and path
func (m *mockRoundTripper) setResponse(method, path string, statusCode int, body string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s %s", method, path)
	m.responses[key] = &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
	m.responses[key].Header.Set("Content-Type", "application/json")
}

// setError sets a mock error for a given method and path
func (m *mockRoundTripper) setError(method, path string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s %s", method, path)
	m.errors[key] = err
}

// getCallCount returns how many times a method/path was called
// Currently unused, but kept for future reference
// func (m *mockRoundTripper) getCallCount(method, path string) int {
// 	m.mu.Lock()
// 	defer m.mu.Unlock()

// 	key := fmt.Sprintf("%s %s", method, path)
// 	return m.callCounts[key]
// }

// mockHTTPClient implements HTTPClient interface using mockRoundTripper
type mockHTTPClient struct {
	transport *mockRoundTripper
	client    *http.Client
}

func newMockHTTPClient() *mockHTTPClient {
	transport := newMockRoundTripper()
	return &mockHTTPClient{
		transport: transport,
		client: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
		},
	}
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.client.Do(req)
}

func (m *mockHTTPClient) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return m.Do(req)
}

// mockKeyringService implements KeyringService interface
type mockKeyringService struct {
	mu    sync.Mutex
	store map[string]map[string]interface{}
	err   error // Error to return on Get/Set operations
}

func newMockKeyringService() *mockKeyringService {
	return &mockKeyringService{
		store: make(map[string]map[string]interface{}),
	}
}

func (m *mockKeyringService) Get(key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.err != nil {
		return "", m.err
	}

	data, ok := m.store[key]
	if !ok {
		return "", fmt.Errorf("key not found: %s", key)
	}

	accessToken, ok := data["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("invalid token format")
	}

	return accessToken, nil
}

func (m *mockKeyringService) Set(key string, data map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.err != nil {
		return m.err
	}

	m.store[key] = data
	return nil
}

// setError sets an error to return on next Get/Set operation
func (m *mockKeyringService) setError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

// clearError clears the error
// Currently unused, but kept for future reference
// func (m *mockKeyringService) clearError() {
// 	m.mu.Lock()
// 	defer m.mu.Unlock()
// 	m.err = nil
// }

// mockFileSystemService implements FileSystemService interface
type mockFileSystemService struct {
	mu       sync.Mutex
	files    map[string][]byte
	dirs     map[string]bool
	env      map[string]string
	readErr  error
	writeErr error
	statErr  error
	mkdirErr error
}

func newMockFileSystemService() *mockFileSystemService {
	return &mockFileSystemService{
		files: make(map[string][]byte),
		dirs:  make(map[string]bool),
		env:   make(map[string]string),
	}
}

// SetFileContent is a test helper to add file content to the mock
func (m *mockFileSystemService) SetFileContent(path string, data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[path] = data
}

func (m *mockFileSystemService) ReadFile(path string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.readErr != nil {
		return nil, m.readErr
	}

	data, ok := m.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}

	return data, nil
}

func (m *mockFileSystemService) WriteFile(path string, data []byte, perm os.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.writeErr != nil {
		return m.writeErr
	}

	m.files[path] = data
	return nil
}

func (m *mockFileSystemService) MkdirAll(path string, perm os.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.mkdirErr != nil {
		return m.mkdirErr
	}

	m.dirs[path] = true
	return nil
}

func (m *mockFileSystemService) Stat(path string) (os.FileInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.statErr != nil {
		return nil, m.statErr
	}

	// Check if file exists
	if _, ok := m.files[path]; ok {
		return &mockFileInfo{name: filepath.Base(path), isDir: false}, nil
	}

	// Check if directory exists
	if _, ok := m.dirs[path]; ok {
		return &mockFileInfo{name: filepath.Base(path), isDir: true}, nil
	}

	return nil, os.ErrNotExist
}

func (m *mockFileSystemService) Getenv(key string) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.env[key]
}

// setEnv sets an environment variable
func (m *mockFileSystemService) setEnv(key, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.env[key] = value
}

// setReadError sets an error to return on ReadFile
// Currently unused, but kept for future reference
// func (m *mockFileSystemService) setReadError(err error) {
// 	m.mu.Lock()
// 	defer m.mu.Unlock()
// 	m.readErr = err
// }

// setWriteError sets an error to return on WriteFile
// Currently unused, but kept for future reference
// func (m *mockFileSystemService) setWriteError(err error) {
// 	m.mu.Lock()
// 	defer m.mu.Unlock()
// 	m.writeErr = err
// }

// setStatError sets an error to return on Stat
// Currently unused, but kept for future reference
// func (m *mockFileSystemService) setStatError(err error) {
// 	m.mu.Lock()
// 	defer m.mu.Unlock()
// 	m.statErr = err
// }

// setMkdirError sets an error to return on MkdirAll
// Currently unused, but kept for future reference
// func (m *mockFileSystemService) setMkdirError(err error) {
// 	m.mu.Lock()
// 	defer m.mu.Unlock()
// 	m.mkdirErr = err
// }

// mockFileInfo implements os.FileInfo
type mockFileInfo struct {
	name  string
	isDir bool
}

func (m *mockFileInfo) Name() string       { return m.name }
func (m *mockFileInfo) Size() int64        { return 0 }
func (m *mockFileInfo) Mode() os.FileMode  { return 0644 }
func (m *mockFileInfo) ModTime() time.Time { return time.Now() }
func (m *mockFileInfo) IsDir() bool        { return m.isDir }
func (m *mockFileInfo) Sys() interface{}   { return nil }

// Test helper functions

func testCloudLoginCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudLoginCommand {
	t.Helper()

	global := &GlobalCmdOptions{}

	return &CloudLoginCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: global,
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
	}
}

func testCloudWhoamiCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudWhoamiCommand {
	t.Helper()

	global := &GlobalCmdOptions{}

	return &CloudWhoamiCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: global,
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
	}
}

func testCloudThreatmodelsCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudThreatmodelsCommand {
	t.Helper()

	global := &GlobalCmdOptions{}

	return &CloudThreatmodelsCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: global,
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
	}
}

func testCloudCreateCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudCreateCommand {
	t.Helper()

	global := &GlobalCmdOptions{}
	specCfg, err := spec.LoadSpecConfig()
	if err != nil {
		t.Fatalf("failed to load spec config: %v", err)
	}

	return &CloudCreateCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: global,
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
		specCfg: specCfg,
	}
}

// Helper function to create JSON response body
func jsonResponse(data interface{}) string {
	jsonData, _ := json.Marshal(data)
	return string(jsonData)
}

// Tests for helper functions

func TestGetAPIBaseURL(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected string
	}{
		{
			name:     "default URL",
			envValue: "",
			expected: "https://api.threatcl.com",
		},
		{
			name:     "custom URL",
			envValue: "https://custom.api.com",
			expected: "https://custom.api.com",
		},
		{
			name:     "custom URL with trailing slash",
			envValue: "https://custom.api.com/",
			expected: "https://custom.api.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsSvc := newMockFileSystemService()
			fsSvc.setEnv("THREATCL_API_URL", tt.envValue)

			result := getAPIBaseURL(fsSvc)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestGetToken(t *testing.T) {
	tests := []struct {
		name          string
		keyringToken  string
		keyringErr    error
		fileToken     string
		fileExists    bool
		expectedToken string
		expectError   bool
	}{
		{
			name:          "token from keyring",
			keyringToken:  "keyring-token",
			keyringErr:    nil,
			expectedToken: "keyring-token",
			expectError:   false,
		},
		{
			name:          "token from file when keyring fails",
			keyringErr:    fmt.Errorf("keyring error"),
			fileToken:     "file-token",
			fileExists:    true,
			expectedToken: "file-token",
			expectError:   false,
		},
		{
			name:        "no token found",
			keyringErr:  fmt.Errorf("keyring error"),
			fileExists:  false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyringSvc := newMockKeyringService()
			if tt.keyringToken != "" {
				keyringSvc.Set("access_token", map[string]interface{}{
					"access_token": tt.keyringToken,
				})
			}
			if tt.keyringErr != nil {
				keyringSvc.setError(tt.keyringErr)
			}

			fsSvc := newMockFileSystemService()
			if tt.fileExists {
				settingsPath := filepath.Join("/tmp", ".config", "threatcl", "settings.json")
				settings := map[string]interface{}{
					"access_token": tt.fileToken,
				}
				settingsJSON, _ := json.Marshal(settings)
				fsSvc.WriteFile(settingsPath, settingsJSON, 0600)
				fsSvc.setEnv("HOME", "/tmp")
			}

			token, err := getToken(keyringSvc, fsSvc)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if token != tt.expectedToken {
					t.Errorf("expected token %q, got %q", tt.expectedToken, token)
				}
			}
		})
	}
}

func TestValidateToken(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		statusCode  int
		httpErr     error
		expected    bool
		expectError bool
	}{
		{
			name:        "valid token",
			token:       "valid-token",
			statusCode:  http.StatusOK,
			expected:    true,
			expectError: false,
		},
		{
			name:        "invalid token",
			token:       "invalid-token",
			statusCode:  http.StatusUnauthorized,
			expected:    false,
			expectError: false,
		},
		{
			name:        "network error",
			token:       "token",
			httpErr:     fmt.Errorf("network error"),
			expectError: true,
		},
		{
			name:        "unexpected status code",
			token:       "token",
			statusCode:  http.StatusInternalServerError,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			fsSvc := newMockFileSystemService()

			if tt.httpErr != nil {
				httpClient.transport.setError("GET", "/api/v1/users/me", tt.httpErr)
			} else {
				body := `{"id":"user123"}`
				httpClient.transport.setResponse("GET", "/api/v1/users/me", tt.statusCode, body)
			}

			valid, err := validateToken(tt.token, httpClient, fsSvc)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if valid != tt.expected {
					t.Errorf("expected valid=%v, got %v", tt.expected, valid)
				}
			}
		})
	}
}
