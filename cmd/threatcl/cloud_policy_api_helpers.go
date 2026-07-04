package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// policyCreateRequest represents the request body for creating a policy
type policyCreateRequest struct {
	Name        string   `json:"name"`
	RegoSource  string   `json:"rego_source"`
	Severity    string   `json:"severity"`
	Description *string  `json:"description,omitempty"`
	Category    *string  `json:"category,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Enabled     *bool    `json:"enabled,omitempty"`
}

// policyUpdateRequest represents the request body for updating a policy
type policyUpdateRequest struct {
	Name        *string  `json:"name,omitempty"`
	Description *string  `json:"description,omitempty"`
	RegoSource  *string  `json:"rego_source,omitempty"`
	Severity    *string  `json:"severity,omitempty"`
	Category    *string  `json:"category,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Enabled     *bool    `json:"enabled,omitempty"`
	Enforced    *bool    `json:"enforced,omitempty"`
}

// fetchPolicies retrieves all policies for an organization
func (c *CloudClient) FetchPolicies() ([]policy, error) {
	apiURL := fmt.Sprintf("%s/api/v1/org/%s/policies", c.baseURL, url.PathEscape(c.orgId))

	resp, err := makeAuthenticatedRequest("GET", apiURL, c.token, nil, c.http)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, handleAPIErrorResponse(resp)
	}

	var policies []policy
	if err := decodeJSONResponse(resp, &policies); err != nil {
		return nil, err
	}

	return policies, nil
}

// fetchPolicy retrieves a single policy by ID
func (c *CloudClient) FetchPolicy(policyId string) (*policy, error) {
	apiURL := fmt.Sprintf("%s/api/v1/org/%s/policies/%s", c.baseURL, url.PathEscape(c.orgId), url.PathEscape(policyId))

	resp, err := makeAuthenticatedRequest("GET", apiURL, c.token, nil, c.http)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, errors.New(ErrAuthFailed)
		}
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("policy not found: %s", policyId)
		}
		return nil, fmt.Errorf(ErrAPIReturnedStatus, resp.StatusCode, string(body))
	}

	var p policy
	if err := decodeJSONResponse(resp, &p); err != nil {
		return nil, err
	}

	return &p, nil
}

// createPolicy creates a new policy
func (c *CloudClient) CreatePolicy(payload *policyCreateRequest) (*policy, error) {
	apiURL := fmt.Sprintf("%s/api/v1/org/%s/policies", c.baseURL, url.PathEscape(c.orgId))

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrFailedToCreateReq, err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrFailedToConnect, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, errors.New(ErrAuthFailed)
		}
		return nil, fmt.Errorf(ErrAPIReturnedStatus, resp.StatusCode, string(body))
	}

	var p policy
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", ErrFailedToParseResp, err)
	}

	return &p, nil
}

// updatePolicy updates an existing policy
func (c *CloudClient) UpdatePolicy(policyId string, payload *policyUpdateRequest) (*policy, error) {
	apiURL := fmt.Sprintf("%s/api/v1/org/%s/policies/%s", c.baseURL, url.PathEscape(c.orgId), url.PathEscape(policyId))

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("PUT", apiURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrFailedToCreateReq, err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrFailedToConnect, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, errors.New(ErrAuthFailed)
		}
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("policy not found: %s", policyId)
		}
		return nil, fmt.Errorf(ErrAPIReturnedStatus, resp.StatusCode, string(body))
	}

	var p policy
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", ErrFailedToParseResp, err)
	}

	return &p, nil
}

// deletePolicy deletes a policy
func (c *CloudClient) DeletePolicy(policyId string) error {
	apiURL := fmt.Sprintf("%s/api/v1/org/%s/policies/%s", c.baseURL, url.PathEscape(c.orgId), url.PathEscape(policyId))

	resp, err := makeAuthenticatedRequest("DELETE", apiURL, c.token, nil, c.http)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return handleAPIErrorResponse(resp)
	}

	return nil
}

// policyEvaluation represents an evaluation run
type policyEvaluation struct {
	ID             string                   `json:"id"`
	OrganizationID string                   `json:"organization_id"`
	ThreatModelID  string                   `json:"threat_model_id"`
	TriggeredBy    string                   `json:"triggered_by"`
	Status         string                   `json:"status"`
	TotalPolicies  int                      `json:"total_policies"`
	PassedCount    int                      `json:"passed_count"`
	FailedCount    int                      `json:"failed_count"`
	ErrorCount     int                      `json:"error_count"`
	DurationMs     int                      `json:"duration_ms"`
	CreatedAt      string                   `json:"created_at"`
	Results        []policyEvaluationResult `json:"results,omitempty"`
}

// policyEvaluationResult represents a single policy result within an evaluation
type policyEvaluationResult struct {
	ID             string         `json:"id"`
	EvaluationID   string         `json:"evaluation_id"`
	PolicyID       string         `json:"policy_id"`
	PolicyName     string         `json:"policy_name"`
	PolicySeverity string         `json:"policy_severity"`
	Passed         bool           `json:"passed"`
	Message        string         `json:"message"`
	Details        map[string]any `json:"details,omitempty"`
	DurationMs     int            `json:"duration_ms"`
	CreatedAt      string         `json:"created_at"`
}

// regoValidateRequest represents the request body for validating rego
type regoValidateRequest struct {
	RegoSource string `json:"rego_source"`
}

// regoValidateResponse represents the response from rego validation
type regoValidateResponse struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

// validateRego validates rego source against the API
func (c *CloudClient) ValidateRego(regoSource string) (*regoValidateResponse, error) {
	apiURL := fmt.Sprintf("%s/api/v1/org/%s/policies/validate", c.baseURL, url.PathEscape(c.orgId))

	payload := regoValidateRequest{RegoSource: regoSource}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	resp, err := makeAuthenticatedRequest("POST", apiURL, c.token, bytes.NewReader(payloadBytes), c.http)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, handleAPIErrorResponse(resp)
	}

	var result regoValidateResponse
	if err := decodeJSONResponse(resp, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// evaluatePolicies triggers policy evaluation against a threat model
func (c *CloudClient) EvaluatePolicies(modelId string) (*policyEvaluation, error) {
	apiURL := fmt.Sprintf("%s/api/v1/org/%s/models/%s/evaluate-policies", c.baseURL, url.PathEscape(c.orgId), url.PathEscape(modelId))

	resp, err := makeAuthenticatedRequest("POST", apiURL, c.token, nil, c.http)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, errors.New(ErrAuthFailed)
		}
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("threat model not found: %s", modelId)
		}
		return nil, fmt.Errorf(ErrAPIReturnedStatus, resp.StatusCode, string(body))
	}

	var eval policyEvaluation
	if err := decodeJSONResponse(resp, &eval); err != nil {
		return nil, err
	}

	return &eval, nil
}

// fetchPolicyEvaluations retrieves all evaluations for a threat model
func (c *CloudClient) FetchPolicyEvaluations(modelId string) ([]policyEvaluation, error) {
	apiURL := fmt.Sprintf("%s/api/v1/org/%s/models/%s/policy-evaluations", c.baseURL, url.PathEscape(c.orgId), url.PathEscape(modelId))

	resp, err := makeAuthenticatedRequest("GET", apiURL, c.token, nil, c.http)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, handleAPIErrorResponse(resp)
	}

	var evals []policyEvaluation
	if err := decodeJSONResponse(resp, &evals); err != nil {
		return nil, err
	}

	return evals, nil
}

// fetchPolicyEvaluation retrieves a single evaluation by ID
func (c *CloudClient) FetchPolicyEvaluation(modelId, evalId string) (*policyEvaluation, error) {
	apiURL := fmt.Sprintf("%s/api/v1/org/%s/models/%s/policy-evaluations/%s", c.baseURL, url.PathEscape(c.orgId), url.PathEscape(modelId), url.PathEscape(evalId))

	resp, err := makeAuthenticatedRequest("GET", apiURL, c.token, nil, c.http)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, errors.New(ErrAuthFailed)
		}
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("evaluation not found: %s", evalId)
		}
		return nil, fmt.Errorf(ErrAPIReturnedStatus, resp.StatusCode, string(body))
	}

	var eval policyEvaluation
	if err := decodeJSONResponse(resp, &eval); err != nil {
		return nil, err
	}

	return &eval, nil
}
