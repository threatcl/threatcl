package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/threatcl/spec"
	"github.com/zenizh/go-capturer"
)

const uploadTestValidHCL = `
spec_version = "0.1.10"

threatmodel "Upload Test Model" {
  author = "test@example.com"
  description = "Test"
}
`

// uploadTestCommand builds a CloudUploadCommand with injected mocks
func uploadTestCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudUploadCommand {
	t.Helper()

	specCfg, err := spec.LoadSpecConfig()
	if err != nil {
		t.Fatalf("failed to load spec config: %v", err)
	}

	return &CloudUploadCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: &GlobalCmdOptions{},
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
		specCfg: specCfg,
	}
}

// uploadTestWriteHCL writes content to a real temp file (the HCL parser reads
// the real filesystem) and returns its path
func uploadTestWriteHCL(t testing.TB, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "upload-test.hcl")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp HCL file: %v", err)
	}
	return path
}

func TestCloudUploadHelp(t *testing.T) {
	cmd := &CloudUploadCommand{}
	help := cmd.Help()

	for _, want := range []string{"threatcl cloud upload", "-model-id", "-org-id"} {
		if !strings.Contains(help, want) {
			t.Errorf("Help text should contain %q", want)
		}
	}
}

func TestCloudUploadSynopsis(t *testing.T) {
	cmd := &CloudUploadCommand{}
	synopsis := cmd.Synopsis()

	if synopsis == "" {
		t.Error("Synopsis should not be empty")
	}

	if !strings.Contains(strings.ToLower(synopsis), "upload") {
		t.Error("Synopsis should mention upload")
	}
}

func TestCloudUploadAutocomplete(t *testing.T) {
	cmd := &CloudUploadCommand{}

	if cmd.AutocompleteArgs() == nil {
		t.Error("AutocompleteArgs should not be nil")
	}

	flags := cmd.AutocompleteFlags()
	if _, ok := flags["-config"]; !ok {
		t.Error("AutocompleteFlags should include -config")
	}
}

func TestCloudUploadArgErrors(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectedOut string
	}{
		{
			name:        "missing model-id",
			args:        []string{"file.hcl"},
			expectedOut: "-model-id is required",
		},
		{
			name:        "missing file path",
			args:        []string{"-model-id", "tm1"},
			expectedOut: "file path is required",
		},
		{
			name:        "multiple files",
			args:        []string{"-model-id", "tm1", "file1.hcl", "file2.hcl"},
			expectedOut: "only one file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := uploadTestCommand(t, newMockHTTPClient(), newMockKeyringService(), newMockFileSystemService())

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run(tt.args)
			})

			if code != 1 {
				t.Errorf("expected exit code 1, got %d", code)
			}

			if !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}
		})
	}
}

func TestCloudUploadInvalidConfigFile(t *testing.T) {
	filePath := uploadTestWriteHCL(t, uploadTestValidHCL)

	cmd := uploadTestCommand(t, newMockHTTPClient(), newMockKeyringService(), newMockFileSystemService())

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-model-id", "tm1", "-config", filepath.Join(t.TempDir(), "missing-config.hcl"), filePath})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "Error loading config file") {
		t.Errorf("expected config load error, got %q", out)
	}
}

func TestCloudUploadInvalidHCL(t *testing.T) {
	filePath := uploadTestWriteHCL(t, "this is not { valid hcl {{{")

	cmd := uploadTestCommand(t, newMockHTTPClient(), newMockKeyringService(), newMockFileSystemService())

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-model-id", "tm1", filePath})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "Error parsing HCL file") {
		t.Errorf("expected HCL parse error, got %q", out)
	}
}

func TestCloudUploadWrongThreatmodelCount(t *testing.T) {
	tests := []struct {
		name        string
		hcl         string
		expectedOut string
	}{
		{
			name:        "no threat models",
			hcl:         "spec_version = \"0.1.10\"\n",
			expectedOut: "must contain exactly one threat model, found 0",
		},
		{
			name: "two threat models",
			hcl: `
spec_version = "0.1.10"

threatmodel "Model One" {
  author = "test@example.com"
  description = "Test"
}

threatmodel "Model Two" {
  author = "test@example.com"
  description = "Test"
}
`,
			expectedOut: "must contain exactly one threat model, found 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := uploadTestWriteHCL(t, tt.hcl)

			cmd := uploadTestCommand(t, newMockHTTPClient(), newMockKeyringService(), newMockFileSystemService())

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run([]string{"-model-id", "tm1", filePath})
			})

			if code != 1 {
				t.Errorf("expected exit code 1, got %d", code)
			}

			if !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}
		})
	}
}

func TestCloudUploadMissingToken(t *testing.T) {
	filePath := uploadTestWriteHCL(t, uploadTestValidHCL)

	keyringSvc := newMockKeyringService()
	keyringSvc.setError(fmt.Errorf("no token"))

	cmd := uploadTestCommand(t, newMockHTTPClient(), keyringSvc, newMockFileSystemService())

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-model-id", "tm1", filePath})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "no tokens found") {
		t.Errorf("expected error about missing tokens, got %q", out)
	}

	if !strings.Contains(out, ErrPleaseLogin) {
		t.Errorf("expected login hint, got %q", out)
	}
}

func TestCloudUploadReadFileError(t *testing.T) {
	// The parser reads the real file, but the upload itself reads via the
	// injected fsSvc; leaving the mock empty triggers the read failure.
	filePath := uploadTestWriteHCL(t, uploadTestValidHCL)

	keyringSvc := newMockKeyringService()
	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	cmd := uploadTestCommand(t, newMockHTTPClient(), keyringSvc, newMockFileSystemService())

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-model-id", "tm1", filePath})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, ErrFailedToReadFile) {
		t.Errorf("expected read failure error, got %q", out)
	}
}

func TestCloudUploadSuccess(t *testing.T) {
	filePath := uploadTestWriteHCL(t, uploadTestValidHCL)

	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")
	fsSvc.SetFileContent(filePath, []byte(uploadTestValidHCL))

	uploadPath := "/api/v1/org/org123/models/tm1/upload"
	httpClient.transport.setResponse("POST", uploadPath, http.StatusOK, `{"success":true}`)

	cmd := uploadTestCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-model-id", "tm1", filePath})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d\nOutput: %s", code, out)
	}

	if !strings.Contains(out, fmt.Sprintf("Successfully uploaded threat model from %s", filePath)) {
		t.Errorf("expected success message, got %q", out)
	}

	bodies := httpClient.transport.getRequestBodies("POST", uploadPath)
	if len(bodies) != 1 {
		t.Fatalf("expected 1 upload request, got %d", len(bodies))
	}

	body := bodies[0]
	if !strings.Contains(body, fmt.Sprintf(`filename="%s"`, filepath.Base(filePath))) {
		t.Errorf("expected multipart body to contain filename %q, got %q", filepath.Base(filePath), body)
	}

	if !strings.Contains(body, "Upload Test Model") {
		t.Errorf("expected multipart body to contain the HCL content, got %q", body)
	}

	if strings.Contains(body, "ignore-linked-controls") {
		t.Errorf("expected multipart body to NOT contain ignore-linked-controls, got %q", body)
	}
}

func TestCloudUploadWithOrgIdFlag(t *testing.T) {
	filePath := uploadTestWriteHCL(t, uploadTestValidHCL)

	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org456", "Other Org")
	fsSvc.SetFileContent(filePath, []byte(uploadTestValidHCL))

	httpClient.transport.setResponse("POST", "/api/v1/org/org456/models/my-slug/upload", http.StatusOK, `{"success":true}`)

	cmd := uploadTestCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-model-id", "my-slug", "-org-id", "org456", filePath})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d\nOutput: %s", code, out)
	}

	if !strings.Contains(out, "Successfully uploaded threat model") {
		t.Errorf("expected success message, got %q", out)
	}
}

func TestCloudUploadAPIErrors(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		httpErr     error
		expectedOut string
	}{
		{
			name:        "unauthorized",
			statusCode:  http.StatusUnauthorized,
			expectedOut: "authentication failed",
		},
		{
			name:        "not found",
			statusCode:  http.StatusNotFound,
			expectedOut: "threat model not found: tm1",
		},
		{
			name:        "server error",
			statusCode:  http.StatusInternalServerError,
			expectedOut: "api returned status 500",
		},
		{
			name:        "network error",
			httpErr:     fmt.Errorf("network error"),
			expectedOut: ErrFailedToConnect,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := uploadTestWriteHCL(t, uploadTestValidHCL)

			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			keyringSvc.setMockToken("valid-token", "org123", "Test Org")
			fsSvc.SetFileContent(filePath, []byte(uploadTestValidHCL))

			uploadPath := "/api/v1/org/org123/models/tm1/upload"
			if tt.httpErr != nil {
				httpClient.transport.setError("POST", uploadPath, tt.httpErr)
			} else {
				httpClient.transport.setResponse("POST", uploadPath, tt.statusCode, `{"error":"error"}`)
			}

			cmd := uploadTestCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run([]string{"-model-id", "tm1", filePath})
			})

			if code != 1 {
				t.Errorf("expected exit code 1, got %d", code)
			}

			if !strings.Contains(out, "Error uploading file") {
				t.Errorf("expected upload error prefix, got %q", out)
			}

			if !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}
		})
	}
}
