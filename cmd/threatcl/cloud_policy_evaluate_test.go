package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

func TestCloudPolicyEvaluateRunSuccess(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	eval := policyEvaluation{
		ID:            "eval-1",
		ThreatModelID: "model-1",
		Status:        "completed",
		TotalPolicies: 2,
		PassedCount:   2,
		FailedCount:   0,
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
				Passed:         true,
				Message:        "All descriptions present",
			},
		},
	}
	httpClient.transport.setResponse("POST", "/api/v1/org/org123/models/model-1/evaluate-policies", http.StatusCreated, jsonResponse(eval))

	cmd := testCloudPolicyEvaluateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-model-id", "model-1"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, "Controls Required") {
		t.Errorf("expected 'Controls Required' in output, got %q", out)
	}

	if !strings.Contains(out, "2/2 passed") {
		t.Errorf("expected '2/2 passed' in output, got %q", out)
	}
}

func TestCloudPolicyEvaluateRunWithoutOrgId(t *testing.T) {
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

	eval := policyEvaluation{
		ID:            "eval-1",
		Status:        "completed",
		TotalPolicies: 1,
		PassedCount:   1,
	}
	httpClient.transport.setResponse("POST", "/api/v1/org/org123/models/model-1/evaluate-policies", http.StatusCreated, jsonResponse(eval))

	cmd := testCloudPolicyEvaluateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-model-id", "model-1"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestCloudPolicyEvaluateRunMissingModelId(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	cmd := testCloudPolicyEvaluateCommand(t, httpClient, keyringSvc, fsSvc)

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

func TestCloudPolicyEvaluateRunNoTokenForOrg(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	cmd := testCloudPolicyEvaluateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-model-id", "model-1", "-org-id", "different-org"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if !strings.Contains(out, "no token found for organization") {
		t.Errorf("expected error message about no token for org, got %q", out)
	}
}

func TestCloudPolicyEvaluateRunFailOnErrorWithErrorFailure(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	eval := policyEvaluation{
		ID:            "eval-1",
		Status:        "completed",
		TotalPolicies: 2,
		PassedCount:   1,
		FailedCount:   1,
		Results: []policyEvaluationResult{
			{
				PolicyName:     "Controls Required",
				PolicySeverity: "error",
				Passed:         false,
				Message:        "Missing controls",
			},
			{
				PolicyName:     "Description Check",
				PolicySeverity: "warning",
				Passed:         true,
				Message:        "OK",
			},
		},
	}
	httpClient.transport.setResponse("POST", "/api/v1/org/org123/models/model-1/evaluate-policies", http.StatusCreated, jsonResponse(eval))

	cmd := testCloudPolicyEvaluateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-model-id", "model-1", "-fail-on-error"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1 due to error-severity failure, got %d", code)
	}
}

func TestCloudPolicyEvaluateRunFailOnErrorWithOnlyWarningFailure(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	eval := policyEvaluation{
		ID:            "eval-1",
		Status:        "completed",
		TotalPolicies: 2,
		PassedCount:   1,
		FailedCount:   1,
		Results: []policyEvaluationResult{
			{
				PolicyName:     "Controls Required",
				PolicySeverity: "error",
				Passed:         true,
				Message:        "OK",
			},
			{
				PolicyName:     "Description Check",
				PolicySeverity: "warning",
				Passed:         false,
				Message:        "Missing descriptions",
			},
		},
	}
	httpClient.transport.setResponse("POST", "/api/v1/org/org123/models/model-1/evaluate-policies", http.StatusCreated, jsonResponse(eval))

	cmd := testCloudPolicyEvaluateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-model-id", "model-1", "-fail-on-error"})
	})

	if code != 0 {
		t.Errorf("expected exit code 0 (only warning failures, not error), got %d", code)
	}
}

func TestCloudPolicyEvaluateRunFailOnWarningWithWarningFailure(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	eval := policyEvaluation{
		ID:            "eval-1",
		Status:        "completed",
		TotalPolicies: 1,
		PassedCount:   0,
		FailedCount:   1,
		Results: []policyEvaluationResult{
			{
				PolicyName:     "Description Check",
				PolicySeverity: "warning",
				Passed:         false,
				Message:        "Missing descriptions",
			},
		},
	}
	httpClient.transport.setResponse("POST", "/api/v1/org/org123/models/model-1/evaluate-policies", http.StatusCreated, jsonResponse(eval))

	cmd := testCloudPolicyEvaluateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-model-id", "model-1", "-fail-on-warning"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1 due to warning-severity failure, got %d", code)
	}
}

func TestCloudPolicyEvaluateRunJSON(t *testing.T) {
	httpClient := newMockHTTPClient()
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	keyringSvc.setMockToken("valid-token", "org123", "Test Org")

	eval := policyEvaluation{
		ID:            "eval-1",
		Status:        "completed",
		TotalPolicies: 1,
		PassedCount:   1,
	}
	httpClient.transport.setResponse("POST", "/api/v1/org/org123/models/model-1/evaluate-policies", http.StatusCreated, jsonResponse(eval))

	cmd := testCloudPolicyEvaluateCommand(t, httpClient, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{"-org-id", "org123", "-model-id", "model-1", "-json"})
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
}

func TestCloudPolicyEvaluateRunAPIErrors(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		responseBody string
		httpErr      error
		expectedCode int
		expectedOut  string
	}{
		{
			name:         "unauthorized",
			statusCode:   http.StatusUnauthorized,
			responseBody: `{"error":"unauthorized"}`,
			expectedCode: 1,
			expectedOut:  "authentication failed",
		},
		{
			name:         "not found",
			statusCode:   http.StatusNotFound,
			responseBody: `{"error":"not_found"}`,
			expectedCode: 1,
			expectedOut:  "threat model not found",
		},
		{
			name:         "bad request",
			statusCode:   http.StatusBadRequest,
			responseBody: `{"error":"no_policies"}`,
			expectedCode: 1,
			expectedOut:  "Error evaluating policies",
		},
		{
			name:         "network error",
			httpErr:      fmt.Errorf("network error"),
			expectedCode: 1,
			expectedOut:  "Error evaluating policies",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			keyringSvc.setMockToken("valid-token", "org123", "Test Org")

			if tt.httpErr != nil {
				httpClient.transport.setError("POST", "/api/v1/org/org123/models/model-1/evaluate-policies", tt.httpErr)
			} else {
				httpClient.transport.setResponse("POST", "/api/v1/org/org123/models/model-1/evaluate-policies", tt.statusCode, tt.responseBody)
			}

			cmd := testCloudPolicyEvaluateCommand(t, httpClient, keyringSvc, fsSvc)

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

func TestCloudPolicyEvaluatePolicies(t *testing.T) {
	httpClient := newMockHTTPClient()
	fsSvc := newMockFileSystemService()

	eval := policyEvaluation{
		ID:            "eval-1",
		Status:        "completed",
		TotalPolicies: 1,
		PassedCount:   1,
	}
	httpClient.transport.setResponse("POST", "/api/v1/org/org123/models/model-1/evaluate-policies", http.StatusCreated, jsonResponse(eval))

	result, err := evaluatePolicies("token", "org123", "model-1", httpClient, fsSvc)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatalf("expected evaluation but got nil")
	}

	if result.ID != "eval-1" {
		t.Errorf("expected evaluation ID %q, got %q", "eval-1", result.ID)
	}
}

func TestCloudPolicyEvaluateDisplayEvaluation(t *testing.T) {
	eval := &policyEvaluation{
		ID:            "eval-1",
		Status:        "completed",
		TotalPolicies: 2,
		PassedCount:   1,
		FailedCount:   1,
		DurationMs:    150,
		CreatedAt:     "2026-03-10T12:00:00Z",
		Results: []policyEvaluationResult{
			{
				PolicyName:     "Controls Required",
				PolicySeverity: "error",
				Passed:         true,
				Message:        "All threats have controls",
			},
			{
				PolicyName:     "Description Check",
				PolicySeverity: "warning",
				Passed:         false,
				Message:        "Missing descriptions",
			},
		},
	}

	out := capturer.CaptureStdout(func() {
		displayEvaluation(eval)
	})

	if !strings.Contains(out, "Controls Required") {
		t.Errorf("expected 'Controls Required' in output, got %q", out)
	}

	if !strings.Contains(out, "PASS") {
		t.Errorf("expected 'PASS' in output, got %q", out)
	}

	if !strings.Contains(out, "FAIL") {
		t.Errorf("expected 'FAIL' in output, got %q", out)
	}

	if !strings.Contains(out, "1/2 passed") {
		t.Errorf("expected '1/2 passed' in output, got %q", out)
	}
}
