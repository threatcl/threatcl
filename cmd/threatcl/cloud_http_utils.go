package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// makeAuthenticatedRequest creates and executes an authenticated API request
func makeAuthenticatedRequest(method, url, token string, body io.Reader, httpClient HTTPClient) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrFailedToCreateReq, err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrFailedToConnect, err)
	}

	return resp, nil
}

// handleAPIErrorResponse processes common API error responses and returns appropriate errors
func handleAPIErrorResponse(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusUnauthorized {
		return errors.New(ErrAuthFailed)
	}

	if resp.StatusCode == http.StatusNotFound {
		return errors.New("resource not found")
	}

	return fmt.Errorf(ErrAPIReturnedStatus, resp.StatusCode, string(body))
}

// decodeJSONResponse decodes JSON response into provided struct
func decodeJSONResponse(resp *http.Response, v interface{}) error {
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return fmt.Errorf("%s: %w", ErrFailedToParseResp, err)
	}
	return nil
}
