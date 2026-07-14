package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/fatih/color"
	"github.com/threatcl/spec"
	"github.com/zenizh/go-capturer"
)

// diffLocalHCL is a threat model backed by the cloud "my-tm" model. It is
// intentionally different from diffCloudHCL below.
const diffLocalHCL = `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
  threatmodel = "my-tm"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Local description"

  threat "SQL Injection" {
    description = "SQLi in login"
    stride = ["Tampering"]

    control "Input validation" {
      description = "validate inputs"
      implemented = true
    }
  }

  threat "Phishing" {
    description = "phishing attack"
  }
}
`

// diffCloudHCL is the "downloaded" cloud version: the threat model description
// changed, the SQL Injection threat changed (description + stride) and gained a
// control, and the Phishing threat was removed.
const diffCloudHCL = `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
  threatmodel = "my-tm"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Cloud description"

  threat "SQL Injection" {
    description = "SQL injection in login form"
    stride = ["Tampering", "Info Disclosure"]

    control "Input validation" {
      description = "validate inputs"
      implemented = true
    }

    control "WAF rule" {
      description = "block at WAF"
    }
  }
}
`

// diffNoSlugHCL has a valid backend but no threatmodel slug, so there is nothing
// to diff against.
const diffNoSlugHCL = `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Local description"
}
`

func diffMockWhoami() string {
	return jsonResponse(whoamiResponse{
		User: userInfo{Email: "test@example.com", FullName: "Test User"},
		Organizations: []orgMembership{
			{Organization: orgInfo{ID: "org-id", Name: "Test Org", Slug: "test-org"}, Role: "admin"},
		},
	})
}

// setupDiffModelMocks registers whoami, the threat model lookup, and a single
// current version with the supplied spec hash (set it to a non-matching value
// to force the "doesn't match latest" branch).
func setupDiffModelMocks(httpClient *mockHTTPClient, specHash string) {
	httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, diffMockWhoami())
	httpClient.transport.setResponse("GET", "/api/v1/org/org-id/models/my-tm", http.StatusOK,
		jsonResponse(threatModel{ID: "tm-123", Name: "My TM", Slug: "my-tm"}))
	httpClient.transport.setResponse("GET", "/api/v1/org/org-id/models/tm-123/versions", http.StatusOK,
		jsonResponse(threatModelVersionsResponse{
			Versions: []threatModelVersion{{ID: "v1", Version: "1.0.0", SpecFileHash: specHash, IsCurrent: true}},
			Total:    1,
		}))
}

func newDiffValidateCmd(t *testing.T, httpClient HTTPClient) *CloudValidateCommand {
	t.Helper()
	keyringSvc := newMockKeyringService()
	keyringSvc.setMockToken("valid-token", "test-org-id", "Test Org")
	cfg, err := spec.LoadSpecConfig()
	if err != nil {
		t.Fatalf("failed to load spec config: %v", err)
	}
	return &CloudValidateCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: &GlobalCmdOptions{},
			httpClient:       httpClient,
			keyringSvc:       keyringSvc,
			fsSvc:            newMockFileSystemService(),
		},
		specCfg: cfg,
	}
}

func writeTempHCLFile(t *testing.T, content string) string {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "test-*.hcl")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	t.Cleanup(func() { os.Remove(tmpFile.Name()) })
	if _, err := tmpFile.Write([]byte(content)); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()
	return tmpFile.Name()
}

func hashOf(content string) string {
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:])
}

func TestCloudValidateDiffShowsDiff(t *testing.T) {
	color.NoColor = true

	httpClient := newMockHTTPClient()
	setupDiffModelMocks(httpClient, "non-matching-hash")
	httpClient.transport.setResponse("GET", "/api/v1/org/org-id/models/my-tm/download", http.StatusOK, diffCloudHCL)

	cmd := newDiffValidateCmd(t, httpClient)
	filePath := writeTempHCLFile(t, diffLocalHCL)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-diff", filePath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d\nOutput: %s", code, out)
	}

	wants := []string{
		"doesn't match the latest version",
		"Structural summary:",
		`~ threat model "Test Model" (description changed)`,
		`~ threat "SQL Injection" (in "Test Model") (description, stride changed)`,
		`+ threat "Phishing" (in "Test Model")`,
		`- control "WAF rule" (in threat "SQL Injection")`,
		"Unified diff (cloud vs local):",
		"@@",
		"Cloud description", // appears on the "-" side of the text diff
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("expected output to contain %q\nfull output:\n%s", w, out)
		}
	}
}

func TestCloudValidateNoDiffFlag(t *testing.T) {
	color.NoColor = true

	httpClient := newMockHTTPClient()
	setupDiffModelMocks(httpClient, "non-matching-hash")
	// Deliberately do NOT register the /download endpoint: without -diff the
	// command must not attempt to download.

	cmd := newDiffValidateCmd(t, httpClient)
	filePath := writeTempHCLFile(t, diffLocalHCL)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{filePath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d\nOutput: %s", code, out)
	}
	if !strings.Contains(out, "doesn't match the latest version") {
		t.Errorf("expected the mismatch message, got: %s", out)
	}
	for _, unwanted := range []string{"Structural summary:", "Unified diff", "could not produce diff"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("did not expect output to contain %q\nfull output:\n%s", unwanted, out)
		}
	}
}

func TestCloudValidateDiffNoSlug(t *testing.T) {
	color.NoColor = true

	httpClient := newMockHTTPClient()
	httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, diffMockWhoami())

	cmd := newDiffValidateCmd(t, httpClient)
	filePath := writeTempHCLFile(t, diffNoSlugHCL)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-diff", filePath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d\nOutput: %s", code, out)
	}
	if !strings.Contains(out, "Organization is valid") {
		t.Errorf("expected 'Organization is valid', got: %s", out)
	}
	if !strings.Contains(out, "no 'threatmodel' slug in the backend block") {
		t.Errorf("expected the no-slug note, got: %s", out)
	}
	if strings.Contains(out, "Unified diff") {
		t.Errorf("did not expect a diff for a model with no slug\nfull output:\n%s", out)
	}
}

func TestCloudValidateDiffDownloadError(t *testing.T) {
	color.NoColor = true

	httpClient := newMockHTTPClient()
	setupDiffModelMocks(httpClient, "non-matching-hash")
	httpClient.transport.setError("GET", "/api/v1/org/org-id/models/my-tm/download", fmt.Errorf("network down"))

	cmd := newDiffValidateCmd(t, httpClient)
	filePath := writeTempHCLFile(t, diffLocalHCL)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-diff", filePath})
	})

	// Diff failure is non-fatal: validation still succeeds.
	if code != 0 {
		t.Fatalf("expected exit code 0 (diff failure is non-fatal), got %d\nOutput: %s", code, out)
	}
	if !strings.Contains(out, "doesn't match the latest version") {
		t.Errorf("expected the mismatch message, got: %s", out)
	}
	if !strings.Contains(out, "could not produce diff") {
		t.Errorf("expected a 'could not produce diff' warning, got: %s", out)
	}
}

func TestCloudValidateDiffMatchesLatest(t *testing.T) {
	color.NoColor = true

	httpClient := newMockHTTPClient()
	// The current version hash matches the local file => nothing to diff.
	setupDiffModelMocks(httpClient, hashOf(diffLocalHCL))

	cmd := newDiffValidateCmd(t, httpClient)
	filePath := writeTempHCLFile(t, diffLocalHCL)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-diff", filePath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d\nOutput: %s", code, out)
	}
	if !strings.Contains(out, "matches the latest version") {
		t.Errorf("expected the matches-latest message, got: %s", out)
	}
	if !strings.Contains(out, "already matches the latest version; nothing to diff") {
		t.Errorf("expected the nothing-to-diff note, got: %s", out)
	}
	if strings.Contains(out, "Unified diff") {
		t.Errorf("did not expect a diff when the file matches latest\nfull output:\n%s", out)
	}
}

func TestCloudValidateDiffUnparseableCloud(t *testing.T) {
	color.NoColor = true

	httpClient := newMockHTTPClient()
	setupDiffModelMocks(httpClient, "non-matching-hash")
	httpClient.transport.setResponse("GET", "/api/v1/org/org-id/models/my-tm/download", http.StatusOK, "this is not valid hcl {{{")

	cmd := newDiffValidateCmd(t, httpClient)
	filePath := writeTempHCLFile(t, diffLocalHCL)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-diff", filePath})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d\nOutput: %s", code, out)
	}
	if !strings.Contains(out, "could not parse cloud version for semantic diff") {
		t.Errorf("expected a semantic-diff parse warning, got: %s", out)
	}
	// The unified text diff should still render even when the cloud side won't parse.
	if !strings.Contains(out, "Unified diff (cloud vs local):") || !strings.Contains(out, "@@") {
		t.Errorf("expected the unified text diff to still render, got: %s", out)
	}
}

func TestSemanticDiff(t *testing.T) {
	local := &spec.ThreatmodelWrapped{
		Threatmodels: []spec.Threatmodel{
			{
				Name:        "TM",
				Description: "old",
				Threats: []*spec.Threat{
					{Name: "T1", Description: "d1", Controls: []*spec.Control{{Name: "C1", Description: "cd1"}}},
					{Name: "T2", Description: "d2"},
				},
			},
		},
	}
	cloud := &spec.ThreatmodelWrapped{
		Threatmodels: []spec.Threatmodel{
			{
				Name:        "TM",
				Description: "new",
				Threats: []*spec.Threat{
					{Name: "T1", Description: "d1-changed", Controls: []*spec.Control{
						{Name: "C1", Description: "cd1"},
						{Name: "C2", Description: "cd2"},
					}},
					{Name: "T3", Description: "d3"},
				},
			},
		},
	}

	got := semanticDiff(local, cloud)
	want := []string{
		`- control "C2" (in threat "T1")`,
		`- threat "T3" (in "TM")`,
		`+ threat "T2" (in "TM")`,
		`~ threat "T1" (in "TM") (description changed)`,
		`~ threat model "TM" (description changed)`,
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d diff lines, got %d:\n%s", len(want), len(got), strings.Join(got, "\n"))
	}
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("missing expected diff line %q\ngot:\n%s", w, strings.Join(got, "\n"))
		}
	}

	// Identical models => no differences.
	if diffs := semanticDiff(local, local); len(diffs) != 0 {
		t.Errorf("expected no diffs for identical models, got: %v", diffs)
	}
}

func TestUnifiedColorDiff(t *testing.T) {
	color.NoColor = true

	out, err := unifiedColorDiff("a\nb\nc\n", "a\nB\nc\n", "local.hcl", "cloud/my-tm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, w := range []string{"@@", "-b", "+B"} {
		if !strings.Contains(out, w) {
			t.Errorf("expected unified diff to contain %q, got:\n%s", w, out)
		}
	}

	same, err := unifiedColorDiff("a\nb\n", "a\nb\n", "local.hcl", "cloud/my-tm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(same, "no textual differences") {
		t.Errorf("expected 'no textual differences' for identical input, got: %s", same)
	}
}

func TestCloudValidateHelpMentionsDiff(t *testing.T) {
	cmd := &CloudValidateCommand{}
	help := cmd.Help()
	if !strings.Contains(help, "-diff") {
		t.Error("Help text should document the -diff flag")
	}
}

// A cloud version that is a child segment of a multi-file model (dotted id,
// extends target in another segment) must still parse for the semantic diff.
func TestParseCloudHCLChildSegment(t *testing.T) {
	cfg, err := spec.LoadSpecConfig()
	if err != nil {
		t.Fatalf("failed to load spec config: %v", err)
	}

	wrapped, err := parseCloudHCL([]byte(preflightChildHCL), "my-tm", cfg)
	if err != nil {
		t.Fatalf("expected child segment to parse cleanly, got: %v", err)
	}
	if len(wrapped.Threatmodels) != 1 || wrapped.Threatmodels[0].Name != "App Frontend" {
		t.Errorf("unexpected parse result: %+v", wrapped.Threatmodels)
	}
	if wrapped.Threatmodels[0].Extends != "app" {
		t.Errorf("expected extends to stay populated, got %q", wrapped.Threatmodels[0].Extends)
	}
}
