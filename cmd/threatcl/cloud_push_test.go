package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/threatcl/spec"
	"github.com/zenizh/go-capturer"
)

func testCloudPushCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudPushCommand {
	t.Helper()

	global := &GlobalCmdOptions{}
	specCfg, err := spec.LoadSpecConfig()
	if err != nil {
		t.Fatalf("failed to load spec config: %v", err)
	}

	return &CloudPushCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: global,
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
		specCfg: specCfg,
	}
}

func TestCloudPushHelp(t *testing.T) {
	cmd := &CloudPushCommand{}
	help := cmd.Help()

	if !strings.Contains(help, "threatcl cloud push") {
		t.Error("Help text should contain command name")
	}

	if !strings.Contains(help, "-no-create") {
		t.Error("Help text should mention -no-create flag")
	}

	if !strings.Contains(help, "-no-update-local") {
		t.Error("Help text should mention -no-update-local flag")
	}

	if !strings.Contains(help, "-ignore-linked-controls") {
		t.Error("Help text should mention -ignore-linked-controls flag")
	}
}

func TestCloudPushSynopsis(t *testing.T) {
	cmd := &CloudPushCommand{}
	synopsis := cmd.Synopsis()

	if synopsis == "" {
		t.Error("Synopsis should not be empty")
	}

	if !strings.Contains(strings.ToLower(synopsis), "push") {
		t.Error("Synopsis should mention push")
	}
}

func TestCloudPushNoFile(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudPushCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "file path is required") {
		t.Errorf("expected error about file path, got %q", out)
	}
}

func TestCloudPushMultipleFiles(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudPushCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"file1.hcl", "file2.hcl"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "only one file") {
		t.Errorf("expected error about multiple files, got %q", out)
	}
}

func TestCloudPushMissingToken(t *testing.T) {
	validHCL := `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`

	tmpFile, err := os.CreateTemp("", "test-*.hcl")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(validHCL)); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setError(fmt.Errorf("no token"))

	cmd := testCloudPushCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{tmpFile.Name()})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "no tokens found") {
		t.Errorf("expected error about token, got %q", out)
	}
}

func TestCloudPushVersionMatches(t *testing.T) {
	validHCL := `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
  threatmodel = "my-tm"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`

	tmpFile, err := os.CreateTemp("", "test-*.hcl")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(validHCL)); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	// Calculate file hash
	fileContent := []byte(validHCL)
	hashBytes := sha256.Sum256(fileContent)
	fileHash := hex.EncodeToString(hashBytes[:])

	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org-id", "Test Org")

	// Set up whoami response
	httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResponse{
		User: userInfo{Email: "test@example.com"},
		Organizations: []orgMembership{
			{Organization: orgInfo{ID: "org-id", Slug: "test-org"}, Role: "admin"},
		},
	}))

	// Set up threat model response
	httpClient.transport.setResponse("GET", "/api/v1/org/org-id/models/my-tm", http.StatusOK, jsonResponse(threatModel{
		ID:   "tm-123",
		Name: "My TM",
		Slug: "my-tm",
	}))

	// Set up versions response with matching hash
	httpClient.transport.setResponse("GET", "/api/v1/org/org-id/models/tm-123/versions", http.StatusOK, jsonResponse(threatModelVersionsResponse{
		Versions: []threatModelVersion{
			{
				ID:           "v1",
				Version:      "1.0.0",
				SpecFileHash: fileHash,
				IsCurrent:    true,
			},
		},
		Total: 1,
	}))

	cmd := testCloudPushCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{tmpFile.Name()})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d\nOutput: %s", code, out)
	}

	if !strings.Contains(out, "Cloud version matches local version") {
		t.Errorf("expected message about version matching, got %q", out)
	}
}

func TestCloudPushUploadNewVersion(t *testing.T) {
	validHCL := `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
  threatmodel = "my-tm"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`

	tmpFile, err := os.CreateTemp("", "test-*.hcl")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(validHCL)); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org-id", "Test Org")

	fsSvc.SetFileContent(tmpFile.Name(), []byte(validHCL))

	// Set up whoami response
	httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResponse{
		User: userInfo{Email: "test@example.com"},
		Organizations: []orgMembership{
			{Organization: orgInfo{ID: "org-id", Slug: "test-org"}, Role: "admin"},
		},
	}))

	// Set up threat model response
	httpClient.transport.setResponse("GET", "/api/v1/org/org-id/models/my-tm", http.StatusOK, jsonResponse(threatModel{
		ID:   "tm-123",
		Name: "My TM",
		Slug: "my-tm",
	}))

	// Set up versions response with different hash (no match)
	httpClient.transport.setResponse("GET", "/api/v1/org/org-id/models/tm-123/versions", http.StatusOK, jsonResponse(threatModelVersionsResponse{
		Versions: []threatModelVersion{
			{
				ID:           "v1",
				Version:      "1.0.0",
				SpecFileHash: "different-hash",
				IsCurrent:    true,
			},
		},
		Total: 1,
	}))

	// Set up upload response
	httpClient.transport.setResponse("POST", "/api/v1/org/org-id/models/my-tm/upload", http.StatusOK, `{"success":true}`)

	cmd := testCloudPushCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{tmpFile.Name()})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d\nOutput: %s", code, out)
	}

	if !strings.Contains(out, "Successfully pushed threat model") {
		t.Errorf("expected success message, got %q", out)
	}
}

func TestCloudPushNoCreateFlag(t *testing.T) {
	validHCL := `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`

	tmpFile, err := os.CreateTemp("", "test-*.hcl")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(validHCL)); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org-id", "Test Org")

	// Set up whoami response
	httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResponse{
		User: userInfo{Email: "test@example.com"},
		Organizations: []orgMembership{
			{Organization: orgInfo{ID: "org-id", Slug: "test-org"}, Role: "admin"},
		},
	}))

	cmd := testCloudPushCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-no-create", tmpFile.Name()})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d\nOutput: %s", code, out)
	}

	if !strings.Contains(out, "not created due to -no-create") {
		t.Errorf("expected no-create message, got %q", out)
	}
}

func TestCloudPushCreateWithNoUpdateLocal(t *testing.T) {
	validHCL := `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test description"
}
`

	tmpFile, err := os.CreateTemp("", "test-*.hcl")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(validHCL)); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org-id", "Test Org")

	// Set up whoami response
	httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResponse{
		User: userInfo{Email: "test@example.com"},
		Organizations: []orgMembership{
			{Organization: orgInfo{ID: "org-id", Slug: "test-org"}, Role: "admin"},
		},
	}))

	// Set up create response
	httpClient.transport.setResponse("POST", "/api/v1/org/org-id/models", http.StatusCreated, jsonResponse(threatModel{
		ID:   "tm-new",
		Name: "Test Model",
		Slug: "test-model",
	}))

	cmd := testCloudPushCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-no-update-local", tmpFile.Name()})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d\nOutput: %s", code, out)
	}

	if !strings.Contains(out, "Created threat model") {
		t.Errorf("expected create message, got %q", out)
	}

	if !strings.Contains(out, "Update your HCL file backend block") {
		t.Errorf("expected instruction to update HCL, got %q", out)
	}

	if !strings.Contains(out, "test-model") {
		t.Errorf("expected slug in output, got %q", out)
	}
}

func TestCloudPushCreateAndUpdateLocal(t *testing.T) {
	validHCL := `spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test description"
}
`

	tmpFile, err := os.CreateTemp("", "test-*.hcl")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(validHCL)); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org-id", "Test Org")

	fsSvc.SetFileContent(tmpFile.Name(), []byte(validHCL))

	// Set up whoami response
	httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResponse{
		User: userInfo{Email: "test@example.com"},
		Organizations: []orgMembership{
			{Organization: orgInfo{ID: "org-id", Slug: "test-org"}, Role: "admin"},
		},
	}))

	// Set up create response
	httpClient.transport.setResponse("POST", "/api/v1/org/org-id/models", http.StatusCreated, jsonResponse(threatModel{
		ID:   "tm-new",
		Name: "Test Model",
		Slug: "test-model",
	}))

	// Set up upload response
	httpClient.transport.setResponse("POST", "/api/v1/org/org-id/models/test-model/upload", http.StatusOK, `{"success":true}`)

	cmd := testCloudPushCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{tmpFile.Name()})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d\nOutput: %s", code, out)
	}

	if !strings.Contains(out, "Created threat model") {
		t.Errorf("expected create message, got %q", out)
	}

	if !strings.Contains(out, "Updated") && !strings.Contains(out, "threatmodel = \"test-model\"") {
		t.Errorf("expected update message, got %q", out)
	}

	if !strings.Contains(out, "Successfully pushed threat model") {
		t.Errorf("expected success message, got %q", out)
	}

	// Check that the file was updated
	updatedContent, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to read updated file: %v", err)
	}

	if !strings.Contains(string(updatedContent), `threatmodel = "test-model"`) {
		t.Errorf("expected file to contain threatmodel slug, got:\n%s", string(updatedContent))
	}
}

func TestCloudPushThreatmodelNotFound(t *testing.T) {
	validHCL := `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
  threatmodel = "nonexistent-tm"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`

	tmpFile, err := os.CreateTemp("", "test-*.hcl")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(validHCL)); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org-id", "Test Org")

	// Set up whoami response
	httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResponse{
		User: userInfo{Email: "test@example.com"},
		Organizations: []orgMembership{
			{Organization: orgInfo{ID: "org-id", Slug: "test-org"}, Role: "admin"},
		},
	}))

	// Set up threat model not found response
	httpClient.transport.setResponse("GET", "/api/v1/org/org-id/models/nonexistent-tm", http.StatusNotFound, `{"error":"not found"}`)

	cmd := testCloudPushCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{tmpFile.Name()})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d\nOutput: %s", code, out)
	}

	if !strings.Contains(out, "nonexistent-tm") || !strings.Contains(out, "not found") {
		t.Errorf("expected specific error about threatmodel not found, got %q", out)
	}
}

func TestCloudPushInvalidOrganization(t *testing.T) {
	validHCL := `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "invalid-org"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`

	tmpFile, err := os.CreateTemp("", "test-*.hcl")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(validHCL)); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org-id", "Test Org")

	// Set up whoami response with different org
	httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResponse{
		User: userInfo{Email: "test@example.com"},
		Organizations: []orgMembership{
			{Organization: orgInfo{ID: "org-id", Slug: "different-org"}, Role: "admin"},
		},
	}))

	cmd := testCloudPushCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{tmpFile.Name()})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d\nOutput: %s", code, out)
	}

	if !strings.Contains(out, "not a member of organization") {
		t.Errorf("expected error about invalid organization, got %q", out)
	}
}

func TestCloudPushUploadError(t *testing.T) {
	validHCL := `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
  threatmodel = "my-tm"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`

	tmpFile, err := os.CreateTemp("", "test-*.hcl")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(validHCL)); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org-id", "Test Org")

	fsSvc.SetFileContent(tmpFile.Name(), []byte(validHCL))

	// Set up whoami response
	httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResponse{
		User: userInfo{Email: "test@example.com"},
		Organizations: []orgMembership{
			{Organization: orgInfo{ID: "org-id", Slug: "test-org"}, Role: "admin"},
		},
	}))

	// Set up threat model response
	httpClient.transport.setResponse("GET", "/api/v1/org/org-id/models/my-tm", http.StatusOK, jsonResponse(threatModel{
		ID:   "tm-123",
		Name: "My TM",
		Slug: "my-tm",
	}))

	// Set up versions response with different hash
	httpClient.transport.setResponse("GET", "/api/v1/org/org-id/models/tm-123/versions", http.StatusOK, jsonResponse(threatModelVersionsResponse{
		Versions: []threatModelVersion{
			{
				ID:           "v1",
				Version:      "1.0.0",
				SpecFileHash: "different-hash",
				IsCurrent:    true,
			},
		},
		Total: 1,
	}))

	// Set up upload error
	httpClient.transport.setError("POST", "/api/v1/org/org-id/models/my-tm/upload", fmt.Errorf("network error"))

	cmd := testCloudPushCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{tmpFile.Name()})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d\nOutput: %s", code, out)
	}

	if !strings.Contains(out, "Error uploading file") {
		t.Errorf("expected upload error message, got %q", out)
	}
}

// setupChildSegmentPushMocks wires the whoami/model/versions/upload responses
// for pushing one child segment file of a multi-file model to the existing
// cloud model "my-tm" in org "org-id".
func setupChildSegmentPushMocks(httpClient *mockHTTPClient, keyringSvc *mockKeyringService) {
	keyringSvc.setMockToken("valid-token", "org-id", "Test Org")

	httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResponse{
		User: userInfo{Email: "test@example.com"},
		Organizations: []orgMembership{
			{Organization: orgInfo{ID: "org-id", Slug: "test-org"}, Role: "admin"},
		},
	}))

	httpClient.transport.setResponse("GET", "/api/v1/org/org-id/models/my-tm", http.StatusOK, jsonResponse(threatModel{
		ID:   "tm-123",
		Name: "App",
		Slug: "my-tm",
	}))

	httpClient.transport.setResponse("GET", "/api/v1/org/org-id/models/tm-123/versions", http.StatusOK, jsonResponse(threatModelVersionsResponse{
		Versions: []threatModelVersion{
			{ID: "v1", Version: "1.0.0", SpecFileHash: "different-hash", IsCurrent: true},
		},
		Total: 1,
	}))

	httpClient.transport.setResponse("POST", "/api/v1/org/org-id/models/my-tm/upload", http.StatusOK, `{"success":true}`)
}

// A child segment file whose extends target lives in another (already
// uploaded) file must not fail the client-side parse; the push request must
// reach the server, which owns whole-set validation.
func TestCloudPushChildSegmentReachesServer(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "frontend.hcl")
	if err := os.WriteFile(filePath, []byte(preflightChildHCL), 0600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	setupChildSegmentPushMocks(httpClient, keyringSvc)
	fsSvc.SetFileContent(filePath, []byte(preflightChildHCL))

	cmd := testCloudPushCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{filePath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d\nOutput: %s", code, out)
	}
	if strings.Contains(out, "extends references unknown threat model") {
		t.Errorf("child segment failed client-side extends resolution: %q", out)
	}
	if !strings.Contains(out, "Successfully pushed threat model") {
		t.Errorf("expected success message, got %q", out)
	}
	// The upload request must actually have reached the (mock) server.
	if uploads := httpClient.transport.getRequestBodies("POST", "/api/v1/org/org-id/models/my-tm/upload"); len(uploads) != 1 {
		t.Errorf("expected exactly one upload request to reach the server, got %d", len(uploads))
	}
	// Without -with, the multi-file hint should point at the local preflight.
	if !strings.Contains(out, "multi-file model") {
		t.Errorf("expected multi-file hint, got %q", out)
	}
}

// A child segment file with no 'threatmodel' in its backend block would fall
// into the create path; creating a fresh cloud model from a child can never
// succeed, so push must refuse before creating an orphan model.
func TestCloudPushChildSegmentCreateGuard(t *testing.T) {
	childNoTM := strings.Replace(preflightChildHCL, "  threatmodel = \"my-tm\"\n", "", 1)

	dir := t.TempDir()
	filePath := filepath.Join(dir, "frontend.hcl")
	if err := os.WriteFile(filePath, []byte(childNoTM), 0600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org-id", "Test Org")
	httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResponse{
		User: userInfo{Email: "test@example.com"},
		Organizations: []orgMembership{
			{Organization: orgInfo{ID: "org-id", Slug: "test-org"}, Role: "admin"},
		},
	}))

	cmd := testCloudPushCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{filePath})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d\nOutput: %s", code, out)
	}
	if !strings.Contains(out, "Push the model's root file first") {
		t.Errorf("expected child segment guard message, got %q", out)
	}
	// No model must have been created.
	if creates := httpClient.transport.getRequestBodies("POST", "/api/v1/org/org-id/models"); len(creates) != 0 {
		t.Errorf("expected no create request, got %d", len(creates))
	}
}

func TestCloudPushWithPreflightPasses(t *testing.T) {
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root.hcl")
	childPath := filepath.Join(dir, "frontend.hcl")
	if err := os.WriteFile(rootPath, []byte(preflightRootHCL), 0600); err != nil {
		t.Fatalf("failed to write root file: %v", err)
	}
	if err := os.WriteFile(childPath, []byte(preflightChildHCL), 0600); err != nil {
		t.Fatalf("failed to write child file: %v", err)
	}

	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	setupChildSegmentPushMocks(httpClient, keyringSvc)
	fsSvc.SetFileContent(childPath, []byte(preflightChildHCL))

	cmd := testCloudPushCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-with", filepath.Join(dir, "*.hcl"), childPath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d\nOutput: %s", code, out)
	}
	if !strings.Contains(out, "Local set preflight passed (2 files)") {
		t.Errorf("expected preflight success message, got %q", out)
	}
	if !strings.Contains(out, "Successfully pushed threat model") {
		t.Errorf("expected success message, got %q", out)
	}
}

func TestCloudPushWithPreflightFails(t *testing.T) {
	badChild := strings.Replace(preflightChildHCL, `extends = "app"`, `extends = "missing"`, 1)

	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root.hcl")
	childPath := filepath.Join(dir, "frontend.hcl")
	if err := os.WriteFile(rootPath, []byte(preflightRootHCL), 0600); err != nil {
		t.Fatalf("failed to write root file: %v", err)
	}
	if err := os.WriteFile(childPath, []byte(badChild), 0600); err != nil {
		t.Fatalf("failed to write child file: %v", err)
	}

	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudPushCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-with", filepath.Join(dir, "*.hcl"), childPath})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d\nOutput: %s", code, out)
	}
	if !strings.Contains(out, "Local set preflight failed") {
		t.Errorf("expected preflight failure message, got %q", out)
	}
	if !strings.Contains(out, "extends references unknown threat model id 'missing'") {
		t.Errorf("expected the set-level extends error, got %q", out)
	}
}
