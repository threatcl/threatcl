package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/threatcl/spec"
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

// createThreatModel creates a new threat model in the cloud
func createThreatModel(token, orgId, name, description string, httpClient HTTPClient, fsSvc FileSystemService) (*threatModel, error) {
	url := fmt.Sprintf("%s/api/v1/org/%s/models", getAPIBaseURL(fsSvc), orgId)

	// Create the request payload
	payload := map[string]string{
		"name":        name,
		"description": description,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create request
	req, err := http.NewRequest("POST", url, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to API: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("authentication failed - token may be invalid or expired. Please run 'threatcl cloud login' again")
		}
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the response
	var tm threatModel
	if err := json.Unmarshal(body, &tm); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &tm, nil
}

// updateHCLBackendThreatmodel updates an HCL file to add the threatmodel slug to the backend block
// Note: This function directly modifies files on disk (not using fsSvc) since it updates user's local files
func updateHCLBackendThreatmodel(filePath, slug string, fsSvc FileSystemService) error {
	// Read file content directly from disk
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	contentStr := string(content)

	// Check if threatmodel is already set in the backend block
	// Look for threatmodel = "..." within a backend "threatcl-cloud" block
	threatmodelPattern := `(backend\s+"threatcl-cloud"\s*\{[^}]*)(threatmodel\s*=\s*"[^"]*")`
	if matched, _ := regexp.MatchString(threatmodelPattern, contentStr); matched {
		return fmt.Errorf("threatmodel is already set in the backend block")
	}

	// Find the organization line within the backend "threatcl-cloud" block and insert threatmodel after it
	// Pattern: within backend "threatcl-cloud" { }, find organization = "..." and add threatmodel after
	orgPattern := regexp.MustCompile(`(backend\s+"threatcl-cloud"\s*\{[^}]*)(organization\s*=\s*"[^"]*")(\s*)`)

	if !orgPattern.MatchString(contentStr) {
		return fmt.Errorf("could not find organization in backend block")
	}

	// Replace by inserting threatmodel after organization line
	updatedContent := orgPattern.ReplaceAllStringFunc(contentStr, func(match string) string {
		// Find where organization line ends and capture the whitespace
		submatches := orgPattern.FindStringSubmatch(match)
		if len(submatches) < 4 {
			return match
		}
		// submatches[1] = everything before organization
		// submatches[2] = organization = "..."
		// submatches[3] = whitespace after organization line

		// Determine indentation by looking at the organization line
		lines := strings.Split(submatches[1]+submatches[2], "\n")
		lastLine := lines[len(lines)-1]
		indent := ""
		for _, ch := range lastLine {
			if ch == ' ' || ch == '\t' {
				indent += string(ch)
			} else {
				break
			}
		}

		// Insert threatmodel on the next line with same indentation
		return submatches[1] + submatches[2] + "\n" + indent + fmt.Sprintf(`threatmodel = "%s"`, slug) + submatches[3]
	})

	// Write updated content back to file directly
	if err := os.WriteFile(filePath, []byte(updatedContent), 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// validateThreatModel validates a local threat model file against a remote threatmodel
// Returns strings for:
// - organization is valid and user can access - return orgid
// - threatmodel name exists - return slug
// - local file matches the latest version of the threatmodel - return version string
func validateThreatModel(token, filePath string, httpClient HTTPClient, fsSvc FileSystemService, specCfg *spec.ThreatmodelSpecConfig) (string, string, string, error) {
	orgValid := ""
	tmNameValid := ""
	tmFileMatchesVersion := ""
	// Step 1: Read the file content to calculate size and hash
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("error reading file: %s", err)
	}

	// Calculate file size and SHA256 hash
	// fileSize := len(fileContent)
	hashBytes := sha256.Sum256(fileContent)
	fileHash := hex.EncodeToString(hashBytes[:])

	// fmt.Printf("File size: %d bytes\n", fileSize)
	// fmt.Printf("File SHA256: %s\n", fileHash)

	// Step 2: Create a temporary file with the same filename
	tmpDir, err := os.MkdirTemp("", "threatcl-validate-")
	if err != nil {
		return orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("error creating temporary directory: %s", err)
	}
	defer os.RemoveAll(tmpDir) // Clean up the entire temp directory

	// Preserve the original filename
	tmpFilePath := filepath.Join(tmpDir, filepath.Base(filePath))
	err = os.WriteFile(tmpFilePath, fileContent, 0600)
	if err != nil {
		return orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("error writing temporary file: %s", err)
	}

	// Step 3: Parse the HCL file from the temporary location
	// fmt.Printf("Parsing threat model file: %s\n", filePath)
	tmParser := spec.NewThreatmodelParser(specCfg)
	err = tmParser.ParseFile(tmpFilePath, false)
	if err != nil {
		return orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("error parsing HCL file: %s", err)
	}
	// fmt.Println("✓ File parsed successfully")

	// Constraint check
	constraintMsg, err := spec.VersionConstraints(tmParser.GetWrapped(), false)
	if err != nil {
		return orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("error checking constraints: %s", err)
	}
	if constraintMsg != "" {
		// @TODO do we want this?
		fmt.Fprintf(os.Stderr, "⚠ Warning: %s\n", constraintMsg)
	}

	// Step 2: Validate backend configuration
	wrapped := tmParser.GetWrapped()

	// Check 1: Exactly one backend block
	if len(wrapped.Backends) == 0 {
		return orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("validation failed: No backend block found. Please add a backend block with backend_name=\"threatcl-cloud\"")
	}

	if len(wrapped.Backends) > 1 {
		return orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("validation failed: Multiple backend blocks found (%d). Only one backend block is allowed", len(wrapped.Backends))
	}
	// fmt.Println("✓ Single backend block found")

	backend := wrapped.Backends[0]

	// Check 2: Backend name is "threatcl-cloud"
	if backend.BackendName != "threatcl-cloud" {
		return orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("validation failed: Backend name is '%s', expected 'threatcl-cloud'", backend.BackendName)
	}
	// fmt.Println("✓ Backend name is 'threatcl-cloud'")

	// Check 3: Backend has organization specified
	if backend.BackendOrg == "" {
		return orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("validation failed: Backend organization is not specified. Please set the 'organization' attribute in the backend block")
	}
	// fmt.Printf("✓ Backend organization specified: %s\n", backend.BackendOrg)

	// Step 4: Fetch user information
	whoamiResp, err := fetchUserInfo(token, httpClient, fsSvc)
	if err != nil {
		return orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("error fetching user information: %s", err)
	}
	// fmt.Printf("✓ User authenticated: %s\n", whoamiResp.User.Email)

	// Step 5: Verify user is member of the specified organization
	var foundOrg *orgMembership
	for _, org := range whoamiResp.Organizations {
		if org.Organization.Slug == backend.BackendOrg {
			foundOrg = &org
			break
		}
	}

	if foundOrg == nil {
		errMsg := fmt.Sprintf("validation failed: User is not a member of organization '%s'.", backend.BackendOrg)
		if len(whoamiResp.Organizations) > 0 {
			errMsg += " Available organizations:"
			for _, org := range whoamiResp.Organizations {
				errMsg += fmt.Sprintf("   - %s (slug: %s, role: %s)", org.Organization.Name, org.Organization.Slug, org.Role)
			}
		}
		return orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("%s", errMsg)
	} else {
		orgValid = foundOrg.Organization.ID
	}

	// fmt.Printf("✓ User is a member of organization '%s' (%s) with role: %s\n",
	// 	foundOrg.Organization.Name,
	// 	foundOrg.Organization.Slug,
	// 	foundOrg.Role)

	if backend.BackendTMShort != "" {
		// Try and match this threat model
		threatModel, err := fetchThreatModel(token, foundOrg.Organization.ID, backend.BackendTMShort, httpClient, fsSvc)
		if err != nil && !strings.Contains(err.Error(), "threat model not found") {
			return orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("error fetching threat models: %s", err)
		}
		if threatModel == nil {
			return orgValid, backend.BackendTMShort, tmFileMatchesVersion, fmt.Errorf("error: backend threatmodel '%s' not found", backend.BackendTMShort)
		} else {
			tmNameValid = threatModel.Slug
			// fmt.Printf("✓ Threat model '%s' found\n", threatModel.Name)

			threatModelVersions, err := fetchThreatModelVersions(token, foundOrg.Organization.ID, threatModel.ID, httpClient, fsSvc)
			if err != nil {
				return orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("error fetching threat model versions: %s", err)
			}

			var foundVersion *threatModelVersion
			latestVersion := false
			for _, version := range threatModelVersions.Versions {
				if version.SpecFileHash == fileHash {
					foundVersion = &version
					latestVersion = version.IsCurrent
					break
				}
			}
			if latestVersion {
				tmFileMatchesVersion = foundVersion.Version
			}
		}
	}
	return orgValid, tmNameValid, tmFileMatchesVersion, nil
}
