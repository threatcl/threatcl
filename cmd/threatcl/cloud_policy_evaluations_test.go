package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

func TestCloudPolicyEvaluationsRunSuccess(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	evals := []policyEvaluation{
		{
			ID:            "eval-1",
			Status:        "completed",
			TotalPolicies: 3,
			PassedCount:   2,
			FailedCount:   1,
			ErrorCount:    0,
			DurationMs:    150,
			CreatedAt:     "2026-03-10T12:00:00Z",
		},
		{
			ID:            "eval-2",
			Status:        "completed",
			TotalPolicies: 3,
			PassedCount:   3,
			FailedCount:   0,
			ErrorCount:    0,
			DurationMs:    120,
			CreatedAt:     "2026-03-09T12:00:00Z",
		},
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/model-1/policy-evaluations", http.StatusOK, jsonResponse(evals))

	cmd := testCloudPolicyEvaluationsCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-model-id", "model-1"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "eval-1") {
		t.Errorf("expected 'eval-1' in output, got %q", out)
	}

	if !strings.Contains(out, "eval-2") {
		t.Errorf("expected 'eval-2' in output, got %q", out)
	}

	if !strings.Contains(out, "completed") {
		t.Errorf("expected 'completed' in output, got %q", out)
	}
}

func TestCloudPolicyEvaluationsRunWithoutOrgId(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	whoamiResp := whoamiResponse{
		Organizations: []orgMembership{
			{
				Organization: orgInfo{
					ID:   "org123",
					Name: "Test Org",
				},
			},
		},
	}
	httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResp))

	evals := []policyEvaluation{}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/model-1/policy-evaluations", http.StatusOK, jsonResponse(evals))

	cmd := testCloudPolicyEvaluationsCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-model-id", "model-1"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestCloudPolicyEvaluationsRunMissingModelId(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudPolicyEvaluationsCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "-model-id is required") {
		t.Errorf("expected error about -model-id being required, got %q", out)
	}
}

func TestCloudPolicyEvaluationsRunEmpty(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/model-1/policy-evaluations", http.StatusOK, "[]")

	cmd := testCloudPolicyEvaluationsCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-model-id", "model-1"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "No evaluations found") {
		t.Errorf("expected 'No evaluations found' in output, got %q", out)
	}
}

func TestCloudPolicyEvaluationsRunJSON(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	evals := []policyEvaluation{
		{
			ID:            "eval-1",
			Status:        "completed",
			TotalPolicies: 1,
			PassedCount:   1,
		},
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/model-1/policy-evaluations", http.StatusOK, jsonResponse(evals))

	cmd := testCloudPolicyEvaluationsCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-model-id", "model-1", "-json"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	var result []policyEvaluation
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &result); err != nil {
		t.Errorf("expected valid JSON output, got error: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("expected 1 evaluation in JSON output, got %d", len(result))
	}
}

func TestCloudPolicyEvaluationsRunAPIErrors(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		httpErr      error
		expectedCode int
		expectedOut  string
	}{
		{
			name:         "unauthorized",
			statusCode:   http.StatusUnauthorized,
			expectedCode: 1,
			expectedOut:  "authentication failed",
		},
		{
			name:         "server error",
			statusCode:   http.StatusInternalServerError,
			expectedCode: 1,
			expectedOut:  "Error fetching evaluations",
		},
		{
			name:         "network error",
			httpErr:      fmt.Errorf("network error"),
			expectedCode: 1,
			expectedOut:  "Error fetching evaluations",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			keyringSvc.setMockToken("valid-token", "org123", "Test Org")

			if tt.httpErr != nil {
				httpClient.transport.setError("GET", "/api/v1/org/org123/models/model-1/policy-evaluations", tt.httpErr)
			} else {
				httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/model-1/policy-evaluations", tt.statusCode, `{"error":"error"}`)
			}

			cmd := testCloudPolicyEvaluationsCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run([]string{"-org-id", "org123", "-model-id", "model-1"})
			})

			if code != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d", tt.expectedCode, code)
			}

			if !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}
		})
	}
}

func TestCloudPolicyFetchPolicyEvaluations(t *testing.T) {
	httpClient := newMockHTTPClient()
	fsSvc := newMockFileSystemService()

	evals := []policyEvaluation{
		{
			ID:     "eval-1",
			Status: "completed",
		},
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/model-1/policy-evaluations", http.StatusOK, jsonResponse(evals))

	result, err := fetchPolicyEvaluations("token", "org123", "model-1", httpClient, fsSvc)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 evaluation, got %d", len(result))
	}

	if result[0].ID != "eval-1" {
		t.Errorf("expected evaluation ID %q, got %q", "eval-1", result[0].ID)
	}
}
