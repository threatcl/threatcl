package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

func TestCloudPolicyEvaluationRunSuccess(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	eval := policyEvaluation{
		ID:            "eval-1",
		ThreatModelID: "model-1",
		Status:        "completed",
		TotalPolicies: 2,
		PassedCount:   1,
		FailedCount:   1,
		ErrorCount:    0,
		DurationMs:    150,
		CreatedAt:     "2026-03-10T12:00:00Z",
		Results: []policyEvaluationResult{
			{
				ID:             "r-1",
				PolicyName:     "Controls Required",
				PolicySeverity: "error",
				Passed:         true,
				Message:        "All threats have controls",
			},
			{
				ID:             "r-2",
				PolicyName:     "Description Check",
				PolicySeverity: "warning",
				Passed:         false,
				Message:        "Missing descriptions",
			},
		},
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/model-1/policy-evaluations/eval-1", http.StatusOK, jsonResponse(eval))

	cmd := testCloudPolicyEvaluationCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-model-id", "model-1", "-eval-id", "eval-1"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "Controls Required") {
		t.Errorf("expected 'Controls Required' in output, got %q", out)
	}

	if !strings.Contains(out, "1/2 passed") {
		t.Errorf("expected '1/2 passed' in output, got %q", out)
	}
}

func TestCloudPolicyEvaluationRunMissingModelId(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudPolicyEvaluationCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-eval-id", "eval-1"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "-model-id is required") {
		t.Errorf("expected error about -model-id being required, got %q", out)
	}
}

func TestCloudPolicyEvaluationRunMissingEvalId(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudPolicyEvaluationCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-model-id", "model-1"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "-eval-id is required") {
		t.Errorf("expected error about -eval-id being required, got %q", out)
	}
}

func TestCloudPolicyEvaluationRunJSON(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	eval := policyEvaluation{
		ID:            "eval-1",
		Status:        "completed",
		TotalPolicies: 1,
		PassedCount:   1,
		Results: []policyEvaluationResult{
			{
				PolicyName:     "Controls Required",
				PolicySeverity: "error",
				Passed:         true,
				Message:        "OK",
			},
		},
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/model-1/policy-evaluations/eval-1", http.StatusOK, jsonResponse(eval))

	cmd := testCloudPolicyEvaluationCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-model-id", "model-1", "-eval-id", "eval-1", "-json"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	var result policyEvaluation
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &result); err != nil {
		t.Errorf("expected valid JSON output, got error: %v", err)
	}

	if result.ID != "eval-1" {
		t.Errorf("expected evaluation ID 'eval-1', got %q", result.ID)
	}

	if len(result.Results) != 1 {
		t.Errorf("expected 1 result, got %d", len(result.Results))
	}
}

func TestCloudPolicyEvaluationRunAPIErrors(t *testing.T) {
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
			name:         "not found",
			statusCode:   http.StatusNotFound,
			expectedCode: 1,
			expectedOut:  "evaluation not found",
		},
		{
			name:         "network error",
			httpErr:      fmt.Errorf("network error"),
			expectedCode: 1,
			expectedOut:  "Error fetching evaluation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			keyringSvc.setMockToken("valid-token", "org123", "Test Org")

			if tt.httpErr != nil {
				httpClient.transport.setError("GET", "/api/v1/org/org123/models/model-1/policy-evaluations/eval-1", tt.httpErr)
			} else {
				httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/model-1/policy-evaluations/eval-1", tt.statusCode, `{"error":"error"}`)
			}

			cmd := testCloudPolicyEvaluationCommand(t, httpClient, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run([]string{"-org-id", "org123", "-model-id", "model-1", "-eval-id", "eval-1"})
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

func TestCloudPolicyFetchPolicyEvaluation(t *testing.T) {
	httpClient := newMockHTTPClient()
	fsSvc := newMockFileSystemService()

	eval := policyEvaluation{
		ID:            "eval-1",
		Status:        "completed",
		TotalPolicies: 2,
		PassedCount:   1,
		FailedCount:   1,
		Results: []policyEvaluationResult{
			{
				PolicyName: "Controls Required",
				Passed:     true,
			},
			{
				PolicyName: "Description Check",
				Passed:     false,
			},
		},
	}
	httpClient.transport.setResponse("GET", "/api/v1/org/org123/models/model-1/policy-evaluations/eval-1", http.StatusOK, jsonResponse(eval))

	result, err := fetchPolicyEvaluation("token", "org123", "model-1", "eval-1", httpClient, fsSvc)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatalf("expected evaluation but got nil")
	}

	if result.ID != "eval-1" {
		t.Errorf("expected evaluation ID %q, got %q", "eval-1", result.ID)
	}

	if len(result.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(result.Results))
	}
}
