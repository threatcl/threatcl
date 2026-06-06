package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/threatcl/spec"
	"github.com/zenizh/go-capturer"
)

// testCloudExportCommand builds a CloudExportCommand with mocked dependencies
// and a real spec config loaded from the package defaults.
func testCloudExportCommand(t testing.TB, httpClient HTTPClient, keyringSvc KeyringService, fsSvc FileSystemService) *CloudExportCommand {
	t.Helper()

	cfg, err := spec.LoadSpecConfig()
	if err != nil {
		t.Fatalf("failed to load spec config: %s", err)
	}

	return &CloudExportCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: &GlobalCmdOptions{},
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            fsSvc,
		},
		specCfg: cfg,
	}
}

// cloudExportSampleHCL is a minimal threat model with one threat ref and one
// control ref. It also includes a backend block so we can assert strip/keep
// behavior. The threat with no ref ensures hydration is selective.
const cloudExportSampleHCL = `spec_version = "0.2.8"

backend "threatcl-cloud" {
  organization = "org-123"
  threatmodel  = "tm1"
}

threatmodel "Sample" {
  author = "tester"

  threat "Ref only" {
    ref = "T-001"
  }

  threat "Local" {
    description = "Locally authored"

    control "Cloud control" {
      ref = "C-001"
    }
  }
}
`

// threatLibraryGQLResponse returns a canned GraphQL response body matching
// the fetchThreatLibraryItemsByRefs query shape.
func threatLibraryGQLResponse() string {
	return `{
		"data": {
			"threatLibraryItemsByRefs": [
				{
					"id": "tlib-1",
					"referenceId": "T-001",
					"name": "Library Threat 1",
					"status": "PUBLISHED",
					"currentVersion": {
						"version": "1.0",
						"name": "Library Threat 1",
						"description": "Resolved threat description from library",
						"impacts": ["Confidentiality"],
						"stride": ["Spoofing"],
						"severity": "high"
					}
				}
			]
		}
	}`
}

// threatLibraryGQLResponseWithRecommended adds a recommended control to T-001.
func threatLibraryGQLResponseWithRecommended() string {
	return `{
		"data": {
			"threatLibraryItemsByRefs": [
				{
					"id": "tlib-1",
					"referenceId": "T-001",
					"name": "Library Threat 1",
					"status": "PUBLISHED",
					"currentVersion": {
						"version": "1.0",
						"name": "Library Threat 1",
						"description": "Resolved threat description from library",
						"recommendedControls": [
							{
								"id": "clib-2",
								"referenceId": "C-RECOMMEND-1",
								"name": "Recommended Control",
								"status": "PUBLISHED",
								"currentVersion": {
									"version": "1.0",
									"name": "Recommended Control",
									"description": "Suggested by the library",
									"implementationGuidance": "Implement broadly"
								}
							}
						]
					}
				}
			]
		}
	}`
}

// controlLibraryGQLResponse returns a canned GraphQL response body for the
// fetchControlLibraryItemsByRefs query.
func controlLibraryGQLResponse() string {
	return `{
		"data": {
			"controlLibraryItemsByRefs": [
				{
					"id": "clib-1",
					"referenceId": "C-001",
					"name": "Library Control 1",
					"status": "PUBLISHED",
					"currentVersion": {
						"version": "1.0",
						"name": "Library Control 1",
						"description": "Resolved control description from library",
						"implementationGuidance": "Implement carefully",
						"defaultRiskReduction": 50
					}
				}
			]
		}
	}`
}

// setupExportMocks wires the model metadata, download, and library responses
// in the sequence the cloud export command expects (threats first, then
// controls). hcl is the body returned from the download endpoint.
func setupExportMocks(
	httpClient *mockHTTPClient,
	keyringSvc *mockKeyringService,
	hcl, threatRespBody, controlRespBody string,
) {
	keyringSvc.setMockToken("valid-token", "org-123", "Test Org")

	httpClient.transport.setResponse("GET", "/api/v1/org/org-123/models/tm1",
		http.StatusOK, jsonResponse(threatModel{ID: "tm1", Name: "Sample", Slug: "sample"}))

	httpClient.transport.setResponse("GET", "/api/v1/org/org-123/models/tm1/download",
		http.StatusOK, hcl)

	httpClient.transport.setResponseSequence("POST", "/api/v1/graphql", []mockResponseData{
		{statusCode: http.StatusOK, body: threatRespBody},
		{statusCode: http.StatusOK, body: controlRespBody},
	})
}

func TestCloudExportMissingModelId(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudExportCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(out, "-model-id is required") {
		t.Errorf("expected -model-id error, got %q", out)
	}
}

func TestCloudExportNoToken(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudExportCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org-123", "-model-id", "tm1"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(out, "no token") && !strings.Contains(out, "no tokens") {
		t.Errorf("expected token error, got %q", out)
	}
}

func TestCloudExportJSONResolvesLibraryRefs(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	setupExportMocks(httpClient, keyringSvc, cloudExportSampleHCL,
		threatLibraryGQLResponse(), controlLibraryGQLResponse())

	cmd := testCloudExportCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{"-org-id", "org-123", "-model-id", "tm1", "-format", "json"})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (output: %s)", code, out)
	}
	if !strings.Contains(out, "Resolved threat description from library") {
		t.Errorf("expected resolved threat description in JSON output, got %q", out)
	}
	if !strings.Contains(out, "Resolved control description from library") {
		t.Errorf("expected resolved control description in JSON output, got %q", out)
	}
	// Local description should remain untouched.
	if !strings.Contains(out, "Locally authored") {
		t.Errorf("expected local threat description to be preserved, got %q", out)
	}
}

func TestCloudExportHCLStripsBackendByDefault(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	setupExportMocks(httpClient, keyringSvc, cloudExportSampleHCL,
		threatLibraryGQLResponse(), controlLibraryGQLResponse())

	cmd := testCloudExportCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{"-org-id", "org-123", "-model-id", "tm1", "-format", "hcl"})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (output: %s)", code, out)
	}
	if strings.Contains(out, "backend \"threatcl-cloud\"") {
		t.Errorf("expected backend block to be stripped, got %q", out)
	}
	if !strings.Contains(out, "Resolved threat description from library") {
		t.Errorf("expected resolved threat description in HCL output, got %q", out)
	}
}

func TestCloudExportHCLKeepBackend(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	setupExportMocks(httpClient, keyringSvc, cloudExportSampleHCL,
		threatLibraryGQLResponse(), controlLibraryGQLResponse())

	cmd := testCloudExportCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-org-id", "org-123", "-model-id", "tm1",
			"-format", "hcl", "-keep-backend",
		})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (output: %s)", code, out)
	}
	if !strings.Contains(out, "backend \"threatcl-cloud\"") {
		t.Errorf("expected backend block to be present with -keep-backend, got %q", out)
	}
}

func TestCloudExportMd(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	setupExportMocks(httpClient, keyringSvc, cloudExportSampleHCL,
		threatLibraryGQLResponse(), controlLibraryGQLResponse())

	cmd := testCloudExportCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{"-org-id", "org-123", "-model-id", "tm1", "-format", "md"})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (output: %s)", code, out)
	}
	if !strings.Contains(out, "Resolved threat description from library") {
		t.Errorf("expected resolved threat description in markdown, got %q", out)
	}
}

func TestCloudExportIncludeRecommended(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	setupExportMocks(httpClient, keyringSvc, cloudExportSampleHCL,
		threatLibraryGQLResponseWithRecommended(), controlLibraryGQLResponse())

	cmd := testCloudExportCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureStdout(func() {
		code = cmd.Run([]string{
			"-org-id", "org-123", "-model-id", "tm1",
			"-format", "json", "-include-recommended",
		})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (output: %s)", code, out)
	}
	if !strings.Contains(out, "C-RECOMMEND-1") {
		t.Errorf("expected recommended control ref in output, got %q", out)
	}
	if !strings.Contains(out, "Suggested by the library") {
		t.Errorf("expected recommended control description in output, got %q", out)
	}
}

func TestCloudExportFileOutput(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	setupExportMocks(httpClient, keyringSvc, cloudExportSampleHCL,
		threatLibraryGQLResponse(), controlLibraryGQLResponse())

	cmd := testCloudExportCommand(t, httpClient, keyringSvc, fsSvc)

	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.json")

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{
			"-org-id", "org-123", "-model-id", "tm1",
			"-format", "json", "-output", outPath,
		})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (output: %s)", code, out)
	}
	if !strings.Contains(out, "Successfully wrote") {
		t.Errorf("expected success message, got %q", out)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("expected output file to exist: %s", err)
	}
	if !strings.Contains(string(data), "Resolved threat description from library") {
		t.Errorf("expected resolved description in file, got %q", string(data))
	}
}

func TestCloudExportFileExistsNoOverwrite(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	setupExportMocks(httpClient, keyringSvc, cloudExportSampleHCL,
		threatLibraryGQLResponse(), controlLibraryGQLResponse())

	cmd := testCloudExportCommand(t, httpClient, keyringSvc, fsSvc)

	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.json")
	if err := os.WriteFile(outPath, []byte("pre-existing"), 0644); err != nil {
		t.Fatalf("setup: %s", err)
	}

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{
			"-org-id", "org-123", "-model-id", "tm1",
			"-format", "json", "-output", outPath,
		})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(out, "already exists") {
		t.Errorf("expected already-exists error, got %q", out)
	}

	// Original contents should be untouched.
	data, _ := os.ReadFile(outPath)
	if string(data) != "pre-existing" {
		t.Errorf("expected original file preserved, got %q", string(data))
	}
}

func TestCloudExportFileExistsOverwrite(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	setupExportMocks(httpClient, keyringSvc, cloudExportSampleHCL,
		threatLibraryGQLResponse(), controlLibraryGQLResponse())

	cmd := testCloudExportCommand(t, httpClient, keyringSvc, fsSvc)

	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.json")
	if err := os.WriteFile(outPath, []byte("pre-existing"), 0644); err != nil {
		t.Fatalf("setup: %s", err)
	}

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{
			"-org-id", "org-123", "-model-id", "tm1",
			"-format", "json", "-output", outPath, "-overwrite",
		})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (output: %s)", code, out)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("expected output file: %s", err)
	}
	if !strings.Contains(string(data), "Resolved threat description from library") {
		t.Errorf("expected resolved content in overwritten file, got %q", string(data))
	}
}

func TestCloudExportDownloadError(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org-123", "Test Org")
	httpClient.transport.setResponse("GET", "/api/v1/org/org-123/models/tm1",
		http.StatusOK, jsonResponse(threatModel{ID: "tm1", Name: "Sample"}))
	httpClient.transport.setResponse("GET", "/api/v1/org/org-123/models/tm1/download",
		http.StatusInternalServerError, `{"error":"boom"}`)

	cmd := testCloudExportCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org-123", "-model-id", "tm1"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(out, "Error downloading threat model file") {
		t.Errorf("expected download error, got %q", out)
	}
}

func TestCloudExportRefMissingWarning(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	// Library returns empty list for both queries -> all refs unresolved.
	emptyResp := `{"data":{"threatLibraryItemsByRefs":[]}}`
	emptyCtrlResp := `{"data":{"controlLibraryItemsByRefs":[]}}`
	setupExportMocks(httpClient, keyringSvc, cloudExportSampleHCL, emptyResp, emptyCtrlResp)

	cmd := testCloudExportCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org-123", "-model-id", "tm1", "-format", "json"})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0 (warning, not error), got %d (output: %s)", code, out)
	}
	if !strings.Contains(out, "unresolved threat refs") {
		t.Errorf("expected unresolved-threat warning, got %q", out)
	}
	if !strings.Contains(out, "unresolved control refs") {
		t.Errorf("expected unresolved-control warning, got %q", out)
	}
}
