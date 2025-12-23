package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"path/filepath"
)

// fetchUserInfo retrieves user information from the API
func fetchUserInfo(token string, httpClient HTTPClient, fsSvc FileSystemService) (*whoamiResponse, error) {
	url := fmt.Sprintf("%s/api/v1/users/me", getAPIBaseURL(fsSvc))

	resp, err := makeAuthenticatedRequest("GET", url, token, nil, httpClient)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, handleAPIErrorResponse(resp)
	}

	var whoamiResp whoamiResponse
	if err := decodeJSONResponse(resp, &whoamiResp); err != nil {
		return nil, err
	}

	return &whoamiResp, nil
}

// uploadFile uploads a threat model file to the API
func uploadFile(token, orgId, modelIdOrSlug, filePath string, httpClient HTTPClient, fsSvc FileSystemService) error {
	url := fmt.Sprintf("%s/api/v1/org/%s/models/%s/upload", getAPIBaseURL(fsSvc), orgId, modelIdOrSlug)

	// Read the file
	fileData, err := fsSvc.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrFailedToReadFile, err)
	}

	// Create multipart form
	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)

	// Add file field
	fileWriter, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return fmt.Errorf("failed to create form file: %w", err)
	}

	_, err = fileWriter.Write(fileData)
	if err != nil {
		return fmt.Errorf("failed to write file data: %w", err)
	}

	// Close the multipart writer
	err = writer.Close()
	if err != nil {
		return fmt.Errorf("failed to close multipart writer: %w", err)
	}

	// Create request
	req, err := http.NewRequest("POST", url, &requestBody)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrFailedToCreateReq, err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Send request
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrFailedToConnect, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			return errors.New(ErrAuthFailed)
		}
		if resp.StatusCode == http.StatusNotFound {
			return fmt.Errorf(ErrThreatModelNotFound, modelIdOrSlug)
		}
		return fmt.Errorf(ErrAPIReturnedStatus, resp.StatusCode, string(body))
	}

	return nil
}

// downloadFile downloads a threat model file from the API
func downloadFile(url, token, downloadPath string, overwrite bool, httpClient HTTPClient, fsSvc FileSystemService) error {
	// Check if file exists and overwrite flag is not set
	if !overwrite {
		if _, err := fsSvc.Stat(downloadPath); err == nil {
			return fmt.Errorf(ErrFileAlreadyExists, downloadPath)
		}
	}

	resp, err := makeAuthenticatedRequest("GET", url, token, nil, httpClient)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return handleAPIErrorResponse(resp)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Write the response body to the file
	err = fsSvc.WriteFile(downloadPath, body, 0644)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrFailedToWriteFile, err)
	}

	return nil
}

// fetchThreatModel retrieves a single threat model
func fetchThreatModel(token, orgId, modelIdOrSlug string, httpClient HTTPClient, fsSvc FileSystemService) (*threatModel, error) {
	url := fmt.Sprintf("%s/api/v1/org/%s/models/%s", getAPIBaseURL(fsSvc), orgId, modelIdOrSlug)

	resp, err := makeAuthenticatedRequest("GET", url, token, nil, httpClient)
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
			return nil, fmt.Errorf(ErrThreatModelNotFound, modelIdOrSlug)
		}
		return nil, fmt.Errorf(ErrAPIReturnedStatus, resp.StatusCode, string(body))
	}

	var threatModel threatModel
	if err := decodeJSONResponse(resp, &threatModel); err != nil {
		return nil, err
	}

	return &threatModel, nil
}

// deleteThreatModel deletes a threat model
func deleteThreatModel(token, orgId, modelIdOrSlug string, httpClient HTTPClient, fsSvc FileSystemService) error {
	url := fmt.Sprintf("%s/api/v1/org/%s/models/%s", getAPIBaseURL(fsSvc), orgId, modelIdOrSlug)

	resp, err := makeAuthenticatedRequest("DELETE", url, token, nil, httpClient)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return handleAPIErrorResponse(resp)
	}

	return nil
}

// updateThreatmodelStatus updates the status of a threat model
func updateThreatmodelStatus(token, orgId, modelIdOrSlug, status string, httpClient HTTPClient, fsSvc FileSystemService) error {
	url := fmt.Sprintf("%s/api/v1/org/%s/models/%s/status", getAPIBaseURL(fsSvc), orgId, modelIdOrSlug)

	// Create the request payload
	payload := map[string]string{
		"status": status,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return handleAPIErrorResponse(resp)
	}

	return nil
}

// fetchThreatModels retrieves all threat models for an organization
func fetchThreatModels(token, orgId string, httpClient HTTPClient, fsSvc FileSystemService) ([]threatModel, error) {
	url := fmt.Sprintf("%s/api/v1/org/%s/models", getAPIBaseURL(fsSvc), orgId)

	resp, err := makeAuthenticatedRequest("GET", url, token, nil, httpClient)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, handleAPIErrorResponse(resp)
	}

	var threatModels []threatModel
	if err := decodeJSONResponse(resp, &threatModels); err != nil {
		return nil, err
	}

	return threatModels, nil
}

// fetchThreatModelVersions retrieves all versions of a threat model
func fetchThreatModelVersions(token, orgId, modelId string, httpClient HTTPClient, fsSvc FileSystemService) (*threatModelVersionsResponse, error) {
	url := fmt.Sprintf("%s/api/v1/org/%s/models/%s/versions", getAPIBaseURL(fsSvc), orgId, modelId)

	resp, err := makeAuthenticatedRequest("GET", url, token, nil, httpClient)
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
			return nil, fmt.Errorf(ErrThreatModelNotFound, modelId)
		}
		return nil, fmt.Errorf(ErrAPIReturnedStatus, resp.StatusCode, string(body))
	}

	var threatModelVersionsResponse threatModelVersionsResponse
	if err := decodeJSONResponse(resp, &threatModelVersionsResponse); err != nil {
		return nil, err
	}

	return &threatModelVersionsResponse, nil
}
