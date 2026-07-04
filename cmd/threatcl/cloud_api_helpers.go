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
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/threatcl/spec"
	"github.com/zclconf/go-cty/cty"
)

// fetchUserInfo retrieves user information from the API
func (c *CloudClient) FetchUserInfo() (*whoamiResponse, error) {
	url := fmt.Sprintf("%s/api/v1/users/me", c.baseURL)

	resp, err := makeAuthenticatedRequest("GET", url, c.token, nil, c.http)
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

// Upload uploads a threat model spec (already-read file bytes) to the API. The
// caller reads the file itself and passes the base filename, so the client
// stays free of filesystem concerns.
func (c *CloudClient) Upload(modelIdOrSlug, filename string, content []byte, ignoreLinkedControls bool) error {
	apiURL := fmt.Sprintf("%s/api/v1/org/%s/models/%s/upload", c.baseURL, url.PathEscape(c.orgId), url.PathEscape(modelIdOrSlug))

	// Create multipart form
	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)

	// Add file field
	fileWriter, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return fmt.Errorf("failed to create form file: %w", err)
	}

	_, err = fileWriter.Write(content)
	if err != nil {
		return fmt.Errorf("failed to write file data: %w", err)
	}

	// Add ignore-linked-controls field if requested
	if ignoreLinkedControls {
		err = writer.WriteField("ignore-linked-controls", "1")
		if err != nil {
			return fmt.Errorf("failed to write ignore-linked-controls field: %w", err)
		}
	}

	// Close the multipart writer
	err = writer.Close()
	if err != nil {
		return fmt.Errorf("failed to close multipart writer: %w", err)
	}

	// Create request
	req, err := http.NewRequest("POST", apiURL, &requestBody)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrFailedToCreateReq, err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Send request
	resp, err := c.http.Do(req)
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

// downloadFileContent downloads a threat model file from the API and returns
// its bytes without touching the filesystem.
func (c *CloudClient) DownloadContent(apiURL string) ([]byte, error) {
	resp, err := makeAuthenticatedRequest("GET", apiURL, c.token, nil, c.http)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, handleAPIErrorResponse(resp)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return body, nil
}

// downloadToFile downloads a threat model file from the API and writes it to
// disk. The network fetch lives on the client (DownloadContent); the overwrite
// check and write stay here so the client stays filesystem-free.
func downloadToFile(client *CloudClient, apiURL, downloadPath string, overwrite bool, fsSvc FileSystemService) error {
	// Check if file exists and overwrite flag is not set
	if !overwrite {
		if _, err := fsSvc.Stat(downloadPath); err == nil {
			return fmt.Errorf(ErrFileAlreadyExists, downloadPath)
		}
	}

	body, err := client.DownloadContent(apiURL)
	if err != nil {
		return err
	}

	if err := fsSvc.WriteFile(downloadPath, body, 0644); err != nil {
		return fmt.Errorf("%s: %w", ErrFailedToWriteFile, err)
	}

	return nil
}

// fetchThreatModel retrieves a single threat model
func (c *CloudClient) FetchThreatModel(modelIdOrSlug string) (*threatModel, error) {
	apiURL := fmt.Sprintf("%s/api/v1/org/%s/models/%s", c.baseURL, url.PathEscape(c.orgId), url.PathEscape(modelIdOrSlug))

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
func (c *CloudClient) DeleteThreatModel(modelIdOrSlug string) error {
	apiURL := fmt.Sprintf("%s/api/v1/org/%s/models/%s", c.baseURL, url.PathEscape(c.orgId), url.PathEscape(modelIdOrSlug))

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

// updateThreatmodelStatus updates the status of a threat model
func (c *CloudClient) UpdateThreatmodelStatus(modelIdOrSlug, status string) error {
	apiURL := fmt.Sprintf("%s/api/v1/org/%s/models/%s/status", c.baseURL, url.PathEscape(c.orgId), url.PathEscape(modelIdOrSlug))

	// Create the request payload
	payload := map[string]string{
		"status": status,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
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
func (c *CloudClient) FetchThreatModels() ([]threatModel, error) {
	apiURL := fmt.Sprintf("%s/api/v1/org/%s/models", c.baseURL, url.PathEscape(c.orgId))

	resp, err := makeAuthenticatedRequest("GET", apiURL, c.token, nil, c.http)
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
func (c *CloudClient) FetchThreatModelVersions(modelId string) (*threatModelVersionsResponse, error) {
	apiURL := fmt.Sprintf("%s/api/v1/org/%s/models/%s/versions", c.baseURL, url.PathEscape(c.orgId), url.PathEscape(modelId))

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
func (c *CloudClient) CreateThreatModel(name, description string) (*threatModel, error) {
	apiURL := fmt.Sprintf("%s/api/v1/org/%s/models", c.baseURL, url.PathEscape(c.orgId))

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
	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := c.http.Do(req)
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
// Returns:
// - wrapped threatmodel (for further validation like control refs)
// - organization is valid and user can access - return orgid
// - threatmodel name exists - return slug
// - local file matches the latest version of the threatmodel - return version string
func validateThreatModel(client *CloudClient, filePath string, specCfg *spec.ThreatmodelSpecConfig) (*spec.ThreatmodelWrapped, string, string, string, error) {
	orgValid := ""
	tmNameValid := ""
	tmFileMatchesVersion := ""
	// Step 1: Read the file content to calculate size and hash
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return nil, orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("error reading file: %s", err)
	}

	// Calculate file size and SHA256 hash from ORIGINAL content (for version matching)
	// fileSize := len(fileContent)
	hashBytes := sha256.Sum256(fileContent)
	fileHash := hex.EncodeToString(hashBytes[:])

	// fmt.Printf("File size: %d bytes\n", fileSize)
	// fmt.Printf("File SHA256: %s\n", fileHash)

	// Preprocess HCL to inject empty descriptions for controls/threats with ref but no description
	// This allows cloud-backed controls and threats to work without requiring local descriptions
	processedContent := preprocessHCLForControls(fileContent)
	processedContent = preprocessHCLForThreats(processedContent)

	// Step 2: Create a temporary file with the same filename
	tmpDir, err := os.MkdirTemp("", "threatcl-validate-")
	if err != nil {
		return nil, orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("error creating temporary directory: %s", err)
	}
	defer os.RemoveAll(tmpDir) // Clean up the entire temp directory

	// Preserve the original filename
	tmpFilePath := filepath.Join(tmpDir, filepath.Base(filePath))
	err = os.WriteFile(tmpFilePath, processedContent, 0600)
	if err != nil {
		return nil, orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("error writing temporary file: %s", err)
	}

	// Step 3: Parse the HCL file from the temporary location
	// fmt.Printf("Parsing threat model file: %s\n", filePath)
	tmParser := spec.NewThreatmodelParser(specCfg)
	err = tmParser.ParseFile(tmpFilePath, false)
	if err != nil {
		return nil, orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("error parsing HCL file: %s", err)
	}
	// fmt.Println("✓ File parsed successfully")

	// Constraint check
	constraintMsg, err := spec.VersionConstraints(tmParser.GetWrapped(), false)
	if err != nil {
		return nil, orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("error checking constraints: %s", err)
	}
	if constraintMsg != "" {
		// @TODO do we want this?
		fmt.Fprintf(os.Stderr, "⚠ Warning: %s\n", constraintMsg)
	}

	// Step 2: Validate backend configuration
	wrapped := tmParser.GetWrapped()

	// Check 1: Exactly one backend block
	if len(wrapped.Backends) == 0 {
		return wrapped, orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("validation failed: No backend block found. Please add a backend block with backend_name=\"threatcl-cloud\"")
	}

	if len(wrapped.Backends) > 1 {
		return wrapped, orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("validation failed: Multiple backend blocks found (%d). Only one backend block is allowed", len(wrapped.Backends))
	}
	// fmt.Println("✓ Single backend block found")

	backend := wrapped.Backends[0]

	// Check 2: Backend name is "threatcl-cloud"
	if backend.BackendName != "threatcl-cloud" {
		return wrapped, orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("validation failed: Backend name is '%s', expected 'threatcl-cloud'", backend.BackendName)
	}
	// fmt.Println("✓ Backend name is 'threatcl-cloud'")

	// Check 3: Backend has organization specified
	if backend.BackendOrg == "" {
		return wrapped, orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("validation failed: Backend organization is not specified. Please set the 'organization' attribute in the backend block")
	}
	// fmt.Printf("✓ Backend organization specified: %s\n", backend.BackendOrg)

	// Step 4: Fetch user information
	whoamiResp, err := client.FetchUserInfo()
	if err != nil {
		return wrapped, orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("error fetching user information: %s", err)
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
		return wrapped, orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("%s", errMsg)
	} else {
		orgValid = foundOrg.Organization.ID
	}

	// fmt.Printf("✓ User is a member of organization '%s' (%s) with role: %s\n",
	// 	foundOrg.Organization.Name,
	// 	foundOrg.Organization.Slug,
	// 	foundOrg.Role)

	if backend.BackendTMShort != "" {
		// Try and match this threat model. The org is resolved from the
		// file's backend block (not the client's construction org), so scope a
		// copy of the client to it.
		orgClient := client.WithOrg(foundOrg.Organization.ID)
		threatModel, err := orgClient.FetchThreatModel(backend.BackendTMShort)
		if err != nil && !strings.Contains(err.Error(), "threat model not found") {
			return wrapped, orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("error fetching threat models: %s", err)
		}
		if threatModel == nil {
			return wrapped, orgValid, backend.BackendTMShort, tmFileMatchesVersion, fmt.Errorf("error: backend threatmodel '%s' not found", backend.BackendTMShort)
		} else {
			tmNameValid = threatModel.Slug
			// fmt.Printf("✓ Threat model '%s' found\n", threatModel.Name)

			threatModelVersions, err := orgClient.FetchThreatModelVersions(threatModel.ID)
			if err != nil {
				return wrapped, orgValid, tmNameValid, tmFileMatchesVersion, fmt.Errorf("error fetching threat model versions: %s", err)
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
	return wrapped, orgValid, tmNameValid, tmFileMatchesVersion, nil
}

// preprocessHCLForControls preprocesses HCL content to inject empty description
// fields into control blocks that have a "ref" attribute but no "description".
// This allows controls to be defined with just a ref, with the description
// being populated from the cloud control library later.
func preprocessHCLForControls(content []byte) []byte {
	// Parse with hclwrite (lenient parser for AST manipulation)
	file, diags := hclwrite.ParseConfig(content, "", hcl.InitialPos)
	if diags.HasErrors() {
		// If parsing fails, return original content and let the normal parser report errors
		return content
	}

	modified := false
	body := file.Body()

	// Find threatmodel blocks → threat blocks → control blocks
	for _, tmBlock := range body.Blocks() {
		if tmBlock.Type() != "threatmodel" {
			continue
		}
		for _, threatBlock := range tmBlock.Body().Blocks() {
			if threatBlock.Type() != "threat" {
				continue
			}
			for _, controlBlock := range threatBlock.Body().Blocks() {
				if controlBlock.Type() != "control" {
					continue
				}
				// If has "ref" but no "description", inject empty description
				hasRef := controlBlock.Body().GetAttribute("ref") != nil
				hasDesc := controlBlock.Body().GetAttribute("description") != nil
				if hasRef && !hasDesc {
					controlBlock.Body().SetAttributeValue("description", cty.StringVal(""))
					modified = true
				}
			}
		}
	}

	if modified {
		return file.Bytes()
	}
	return content
}

// preprocessHCLForThreats preprocesses HCL content to inject empty description
// fields into threat blocks that have a "ref" attribute but no "description".
// This allows threats to be defined with just a ref, with the description
// being populated from the cloud threat library later.
func preprocessHCLForThreats(content []byte) []byte {
	// Parse with hclwrite (lenient parser for AST manipulation)
	file, diags := hclwrite.ParseConfig(content, "", hcl.InitialPos)
	if diags.HasErrors() {
		// If parsing fails, return original content and let the normal parser report errors
		return content
	}

	modified := false
	body := file.Body()

	// Find threatmodel blocks → threat blocks
	for _, tmBlock := range body.Blocks() {
		if tmBlock.Type() != "threatmodel" {
			continue
		}
		for _, threatBlock := range tmBlock.Body().Blocks() {
			if threatBlock.Type() != "threat" {
				continue
			}
			// If has "ref" but no "description", inject empty description
			hasRef := threatBlock.Body().GetAttribute("ref") != nil
			hasDesc := threatBlock.Body().GetAttribute("description") != nil
			if hasRef && !hasDesc {
				threatBlock.Body().SetAttributeValue("description", cty.StringVal(""))
				modified = true
			}
		}
	}

	if modified {
		return file.Bytes()
	}
	return content
}

// stripRemoteFetchDirectives removes the HCL constructs that make the spec
// parser fetch remote content via go-getter: the top-level "imports" attribute
// and each threatmodel block's "including" attribute. Both take a source
// string that go-getter resolves with no scheme/host allowlist (http(s)://,
// git::, s3::, file://, ...).
//
// This is applied to HCL *downloaded from the cloud API* before it is parsed.
// That content is not authored by the local user - it can come from another
// member of a shared org (or a compromised backend) - so resolving these
// directives on the user's machine would be an SSRF / local-file-read
// primitive. Locally-authored files (cloud push/validate of a user's own
// file) are deliberately NOT passed through this, so their imports/including
// continue to work.
func stripRemoteFetchDirectives(content []byte) []byte {
	// Parse with hclwrite (lenient parser for AST manipulation)
	file, diags := hclwrite.ParseConfig(content, "", hcl.InitialPos)
	if diags.HasErrors() {
		// If parsing fails, return original content and let the normal parser
		// report errors.
		return content
	}

	modified := false
	body := file.Body()

	// Top-level "imports = [...]"
	if body.GetAttribute("imports") != nil {
		body.RemoveAttribute("imports")
		modified = true
	}

	// Per-threatmodel "including = ..."
	for _, tmBlock := range body.Blocks() {
		if tmBlock.Type() != "threatmodel" {
			continue
		}
		if tmBlock.Body().GetAttribute("including") != nil {
			tmBlock.Body().RemoveAttribute("including")
			modified = true
		}
	}

	if modified {
		return file.Bytes()
	}
	return content
}

// extractControlRefs extracts all unique control refs from a wrapped threatmodel
func extractControlRefs(wrapped *spec.ThreatmodelWrapped) []string {
	if wrapped == nil {
		return nil
	}

	seen := make(map[string]bool)
	var refs []string

	for _, tm := range wrapped.Threatmodels {
		for _, threat := range tm.Threats {
			for _, control := range threat.Controls {
				if control.Ref != "" && !seen[control.Ref] {
					seen[control.Ref] = true
					refs = append(refs, control.Ref)
				}
			}
		}
	}

	return refs
}

// extractThreatRefs extracts all unique threat refs from a wrapped threatmodel
func extractThreatRefs(wrapped *spec.ThreatmodelWrapped) []string {
	if wrapped == nil {
		return nil
	}

	seen := make(map[string]bool)
	var refs []string

	for _, tm := range wrapped.Threatmodels {
		for _, threat := range tm.Threats {
			if threat.Ref != "" && !seen[threat.Ref] {
				seen[threat.Ref] = true
				refs = append(refs, threat.Ref)
			}
		}
	}

	return refs
}

// extractInformationAssetRefs extracts all unique information_asset refs from a
// wrapped threatmodel.
func extractInformationAssetRefs(wrapped *spec.ThreatmodelWrapped) []string {
	if wrapped == nil {
		return nil
	}

	seen := make(map[string]bool)
	var refs []string

	for _, tm := range wrapped.Threatmodels {
		for _, asset := range tm.InformationAssets {
			if asset == nil {
				continue
			}
			if asset.Ref != "" && !seen[asset.Ref] {
				seen[asset.Ref] = true
				refs = append(refs, asset.Ref)
			}
		}
	}

	return refs
}

// validateControlRefs validates that control refs exist in the library
// Returns a map of ref -> *controlLibraryItem (for found items), a slice of missing refs, and an error
func (c *CloudClient) ValidateControlRefs(refs []string) (map[string]*controlLibraryItem, []string, error) {
	if len(refs) == 0 {
		return nil, nil, nil
	}

	items, err := c.FetchControlLibraryItemsByRefs(refs)
	if err != nil {
		return nil, nil, err
	}

	// Build lookup map of found items
	found := make(map[string]*controlLibraryItem)
	for _, item := range items {
		if item != nil {
			found[item.ReferenceID] = item
		}
	}

	// Find missing refs
	var missing []string
	for _, ref := range refs {
		if found[ref] == nil {
			missing = append(missing, ref)
		}
	}

	return found, missing, nil
}

// fetchControlLibraryItemByRef retrieves a control library item by its reference ID
func (c *CloudClient) FetchControlLibraryItemByRef(refId string) (*controlLibraryItem, error) {
	query := `query controlLibraryItemByRef($orgId: ID!, $referenceId: String!) {
  controlLibraryItemByRef(orgId: $orgId, referenceId: $referenceId) {
    id
    referenceId
    name
    status
    currentVersion {
      version
      name
      description
      controlType
      controlCategory
      implementationGuidance
      nistControls
      cisControls
      isoControls
      tags
      relatedThreats {
        referenceId
        name
      }
      defaultRiskReduction
    }
    versions {
      version
      name
    }
    usageCount
    usedByModels {
      id
      name
    }
  }
}`

	reqBody := graphQLRequest{
		Query: query,
		Variables: map[string]interface{}{
			"orgId":       c.orgId,
			"referenceId": refId,
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/graphql", c.baseURL)
	resp, err := makeAuthenticatedRequest("POST", url, c.token, bytes.NewReader(jsonData), c.http)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, handleAPIErrorResponse(resp)
	}

	var gqlResp graphQLResponse
	if err := decodeJSONResponse(resp, &gqlResp); err != nil {
		return nil, err
	}

	if len(gqlResp.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL error: %s", gqlResp.Errors[0].Message)
	}

	var data struct {
		ControlLibraryItemByRef *controlLibraryItem `json:"controlLibraryItemByRef"`
	}
	if err := json.Unmarshal(gqlResp.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to parse control library item: %w", err)
	}

	if data.ControlLibraryItemByRef == nil {
		return nil, fmt.Errorf(ErrLibraryControlNotFound, refId)
	}

	return data.ControlLibraryItemByRef, nil
}

// fetchControlLibraryItemsByRefs retrieves multiple control library items by their reference IDs
func (c *CloudClient) FetchControlLibraryItemsByRefs(refIds []string) ([]*controlLibraryItem, error) {
	query := `query controlLibraryItemsByRefs($orgId: ID!, $referenceIds: [String!]!) {
  controlLibraryItemsByRefs(orgId: $orgId, referenceIds: $referenceIds) {
    id
    referenceId
    name
    status
    currentVersion {
      version
      name
      description
      controlType
      controlCategory
      implementationGuidance
      nistControls
      cisControls
      isoControls
      tags
      relatedThreats {
        referenceId
        name
      }
      defaultRiskReduction
    }
    versions {
      version
      name
    }
    usageCount
    usedByModels {
      id
      name
    }
  }
}`

	reqBody := graphQLRequest{
		Query: query,
		Variables: map[string]any{
			"orgId":        c.orgId,
			"referenceIds": refIds,
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/graphql", c.baseURL)
	resp, err := makeAuthenticatedRequest("POST", url, c.token, bytes.NewReader(jsonData), c.http)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, handleAPIErrorResponse(resp)
	}

	var gqlResp graphQLResponse
	if err := decodeJSONResponse(resp, &gqlResp); err != nil {
		return nil, err
	}

	if len(gqlResp.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL error: %s", gqlResp.Errors[0].Message)
	}

	var data struct {
		ControlLibraryItemsByRefs []*controlLibraryItem `json:"controlLibraryItemsByRefs"`
	}
	if err := json.Unmarshal(gqlResp.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to parse control library items: %w", err)
	}

	return data.ControlLibraryItemsByRefs, nil
}

// fetchThreatLibraryItemByRef retrieves a threat library item by its reference ID
func (c *CloudClient) FetchThreatLibraryItemByRef(refId string) (*threatLibraryItem, error) {
	query := `query threatLibraryItemByRef($orgId: ID!, $referenceId: String!) {
  threatLibraryItemByRef(orgId: $orgId, referenceId: $referenceId) {
    id
    referenceId
    name
    status
    currentVersion {
      version
      name
      description
      impacts
      stride
      severity
      likelihood
      cweIds
      mitreAttackIds
      tags
    }
    versions {
      version
      name
    }
    usageCount
    usedByModels {
      id
      name
    }
  }
}`

	reqBody := graphQLRequest{
		Query: query,
		Variables: map[string]any{
			"orgId":       c.orgId,
			"referenceId": refId,
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/graphql", c.baseURL)
	resp, err := makeAuthenticatedRequest("POST", url, c.token, bytes.NewReader(jsonData), c.http)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, handleAPIErrorResponse(resp)
	}

	var gqlResp graphQLResponse
	if err := decodeJSONResponse(resp, &gqlResp); err != nil {
		return nil, err
	}

	if len(gqlResp.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL error: %s", gqlResp.Errors[0].Message)
	}

	var data struct {
		ThreatLibraryItemByRef *threatLibraryItem `json:"threatLibraryItemByRef"`
	}
	if err := json.Unmarshal(gqlResp.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to parse threat library item: %w", err)
	}

	if data.ThreatLibraryItemByRef == nil {
		return nil, fmt.Errorf(ErrLibraryThreatNotFound, refId)
	}

	return data.ThreatLibraryItemByRef, nil
}

// fetchThreatLibraryItemsByRefs retrieves multiple threat library items by their reference IDs
// If includeRecommendedControls is true, the query will also fetch full details for recommended controls
func (c *CloudClient) FetchThreatLibraryItemsByRefs(refIds []string, includeRecommendedControls bool) ([]*threatLibraryItem, error) {
	// Base query without recommended controls
	query := `query threatLibraryItemsByRefs($orgId: ID!, $referenceIds: [String!]!) {
  threatLibraryItemsByRefs(orgId: $orgId, referenceIds: $referenceIds) {
    id
    referenceId
    name
    status
    currentVersion {
      version
      name
      description
      impacts
      stride
      severity
      likelihood
      cweIds
      mitreAttackIds
      tags
    }
    versions {
      version
      name
    }
    usageCount
    usedByModels {
      id
      name
    }
  }
}`

	// Extended query with recommended controls
	if includeRecommendedControls {
		query = `query threatLibraryItemsByRefs($orgId: ID!, $referenceIds: [String!]!) {
  threatLibraryItemsByRefs(orgId: $orgId, referenceIds: $referenceIds) {
    id
    referenceId
    name
    status
    currentVersion {
      version
      name
      description
      impacts
      stride
      severity
      likelihood
      cweIds
      mitreAttackIds
      tags
      recommendedControls {
        id
        referenceId
        name
        status
        currentVersion {
          version
          name
          description
          controlType
          controlCategory
          implementationGuidance
          nistControls
          cisControls
          isoControls
          tags
          defaultRiskReduction
        }
      }
    }
    versions {
      version
      name
    }
    usageCount
    usedByModels {
      id
      name
    }
  }
}`
	}

	reqBody := graphQLRequest{
		Query: query,
		Variables: map[string]any{
			"orgId":        c.orgId,
			"referenceIds": refIds,
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/graphql", c.baseURL)
	resp, err := makeAuthenticatedRequest("POST", url, c.token, bytes.NewReader(jsonData), c.http)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, handleAPIErrorResponse(resp)
	}

	var gqlResp graphQLResponse
	if err := decodeJSONResponse(resp, &gqlResp); err != nil {
		return nil, err
	}

	if len(gqlResp.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL error: %s", gqlResp.Errors[0].Message)
	}

	var data struct {
		ThreatLibraryItemsByRefs []*threatLibraryItem `json:"threatLibraryItemsByRefs"`
	}
	if err := json.Unmarshal(gqlResp.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to parse threat library items: %w", err)
	}

	return data.ThreatLibraryItemsByRefs, nil
}

// validateThreatRefs validates that threat refs exist in the library
// If includeRecommendedControls is true, the returned items will include full details for recommended controls
// Returns a map of ref -> *threatLibraryItem (for found items), a slice of missing refs, and an error
func (c *CloudClient) ValidateThreatRefs(refs []string, includeRecommendedControls bool) (map[string]*threatLibraryItem, []string, error) {
	if len(refs) == 0 {
		return nil, nil, nil
	}

	items, err := c.FetchThreatLibraryItemsByRefs(refs, includeRecommendedControls)
	if err != nil {
		return nil, nil, err
	}

	// Build lookup map of found items
	found := make(map[string]*threatLibraryItem)
	for _, item := range items {
		if item != nil {
			found[item.ReferenceID] = item
		}
	}

	// Find missing refs
	var missing []string
	for _, ref := range refs {
		if found[ref] == nil {
			missing = append(missing, ref)
		}
	}

	return found, missing, nil
}

// fetchInformationAssetLibraryItemByRef retrieves an information-asset library
// item by its reference ID.
func (c *CloudClient) FetchInformationAssetLibraryItemByRef(refId string) (*informationAssetLibraryItem, error) {
	query := `query informationAssetLibraryItemByRef($orgId: ID!, $referenceId: String!) {
  informationAssetLibraryItemByRef(orgId: $orgId, referenceId: $referenceId) {
    id
    referenceId
    name
    status
    currentVersion {
      version
      versionNumber
      isPublished
      name
      description
      informationClassification
      source
      changeSummary
      createdAt
    }
    versions {
      version
      versionNumber
      isPublished
      name
      createdAt
    }
    usageCount
    usedByModels {
      id
      name
    }
  }
}`

	reqBody := graphQLRequest{
		Query: query,
		Variables: map[string]any{
			"orgId":       c.orgId,
			"referenceId": refId,
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/graphql", c.baseURL)
	resp, err := makeAuthenticatedRequest("POST", url, c.token, bytes.NewReader(jsonData), c.http)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, handleAPIErrorResponse(resp)
	}

	var gqlResp graphQLResponse
	if err := decodeJSONResponse(resp, &gqlResp); err != nil {
		return nil, err
	}

	if len(gqlResp.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL error: %s", gqlResp.Errors[0].Message)
	}

	var data struct {
		InformationAssetLibraryItemByRef *informationAssetLibraryItem `json:"informationAssetLibraryItemByRef"`
	}
	if err := json.Unmarshal(gqlResp.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to parse information asset library item: %w", err)
	}

	if data.InformationAssetLibraryItemByRef == nil {
		return nil, fmt.Errorf(ErrLibraryAssetNotFound, refId)
	}

	return data.InformationAssetLibraryItemByRef, nil
}

// fetchInformationAssetLibraryItemsByRefs retrieves multiple information-asset
// library items by their reference IDs.
func (c *CloudClient) FetchInformationAssetLibraryItemsByRefs(refIds []string) ([]*informationAssetLibraryItem, error) {
	query := `query informationAssetLibraryItemsByRefs($orgId: ID!, $referenceIds: [String!]!) {
  informationAssetLibraryItemsByRefs(orgId: $orgId, referenceIds: $referenceIds) {
    id
    referenceId
    name
    status
    currentVersion {
      version
      versionNumber
      isPublished
      name
      description
      informationClassification
      source
      changeSummary
      createdAt
    }
    versions {
      version
      versionNumber
      isPublished
      name
      createdAt
    }
    usageCount
    usedByModels {
      id
      name
    }
  }
}`

	reqBody := graphQLRequest{
		Query: query,
		Variables: map[string]any{
			"orgId":        c.orgId,
			"referenceIds": refIds,
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/graphql", c.baseURL)
	resp, err := makeAuthenticatedRequest("POST", url, c.token, bytes.NewReader(jsonData), c.http)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, handleAPIErrorResponse(resp)
	}

	var gqlResp graphQLResponse
	if err := decodeJSONResponse(resp, &gqlResp); err != nil {
		return nil, err
	}

	if len(gqlResp.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL error: %s", gqlResp.Errors[0].Message)
	}

	var data struct {
		InformationAssetLibraryItemsByRefs []*informationAssetLibraryItem `json:"informationAssetLibraryItemsByRefs"`
	}
	if err := json.Unmarshal(gqlResp.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to parse information asset library items: %w", err)
	}

	return data.InformationAssetLibraryItemsByRefs, nil
}

// validateInformationAssetRefs validates that information-asset refs exist in
// the library. Returns a map of ref -> *informationAssetLibraryItem (for found
// items), a slice of missing refs, and an error.
func (c *CloudClient) ValidateInformationAssetRefs(refs []string) (map[string]*informationAssetLibraryItem, []string, error) {
	if len(refs) == 0 {
		return nil, nil, nil
	}

	items, err := c.FetchInformationAssetLibraryItemsByRefs(refs)
	if err != nil {
		return nil, nil, err
	}

	// Build lookup map of found items
	found := make(map[string]*informationAssetLibraryItem)
	for _, item := range items {
		if item != nil {
			found[item.ReferenceID] = item
		}
	}

	// Find missing refs
	var missing []string
	for _, ref := range refs {
		if found[ref] == nil {
			missing = append(missing, ref)
		}
	}

	return found, missing, nil
}

// controlFromLibraryItem creates a new spec.Control populated from a cloud
// control library item. Used when appending library-recommended controls to a
// hydrated threat.
func controlFromLibraryItem(item *controlLibraryItem) *spec.Control {
	if item == nil {
		return nil
	}
	ctrl := &spec.Control{
		Name: item.Name,
		Ref:  item.ReferenceID,
	}
	if item.CurrentVersion != nil {
		ctrl.Description = item.CurrentVersion.Description
		ctrl.ImplementationNotes = item.CurrentVersion.ImplementationGuidance
		ctrl.RiskReduction = item.CurrentVersion.DefaultRiskReduction
	}
	return ctrl
}

// hydrateLibraryRefs fills in description/impact/stride/risk fields on threats
// and controls, and description/classification/source on information assets,
// in a parsed threat model from cloud library items. Local values always
// win — only empty fields are populated. When includeRecommended is true,
// library-recommended controls for each resolved threat ref are appended to
// that threat's controls (deduped by ref).
//
// The information asset's label (Name) is never overlaid — other blocks
// (threat.information_asset_refs, dfd data_store.information_asset) reference
// assets by that label.
func hydrateLibraryRefs(
	wrapped *spec.ThreatmodelWrapped,
	threatItems map[string]*threatLibraryItem,
	controlItems map[string]*controlLibraryItem,
	assetItems map[string]*informationAssetLibraryItem,
	includeRecommended bool,
) {
	if wrapped == nil {
		return
	}

	for tmIdx := range wrapped.Threatmodels {
		tm := &wrapped.Threatmodels[tmIdx]
		for _, threat := range tm.Threats {
			if threat == nil {
				continue
			}

			if threat.Ref != "" {
				if item, ok := threatItems[threat.Ref]; ok && item != nil && item.CurrentVersion != nil {
					v := item.CurrentVersion
					if threat.Description == "" {
						threat.Description = v.Description
					}
					if len(threat.ImpactType) == 0 && len(v.Impacts) > 0 {
						threat.ImpactType = append(threat.ImpactType, v.Impacts...)
					}
					if len(threat.Stride) == 0 && len(v.Stride) > 0 {
						threat.Stride = append(threat.Stride, v.Stride...)
					}

					if includeRecommended && len(v.RecommendedControls) > 0 {
						existing := make(map[string]bool)
						for _, c := range threat.Controls {
							if c != nil && c.Ref != "" {
								existing[c.Ref] = true
							}
						}
						for _, rec := range v.RecommendedControls {
							if rec == nil || rec.ReferenceID == "" {
								continue
							}
							if existing[rec.ReferenceID] {
								continue
							}
							if added := controlFromLibraryItem(rec); added != nil {
								threat.Controls = append(threat.Controls, added)
								existing[rec.ReferenceID] = true
							}
						}
					}
				}
			}

			for _, ctrl := range threat.Controls {
				if ctrl == nil || ctrl.Ref == "" {
					continue
				}
				item, ok := controlItems[ctrl.Ref]
				if !ok || item == nil || item.CurrentVersion == nil {
					continue
				}
				v := item.CurrentVersion
				if ctrl.Description == "" {
					ctrl.Description = v.Description
				}
				if ctrl.ImplementationNotes == "" {
					ctrl.ImplementationNotes = v.ImplementationGuidance
				}
				if ctrl.RiskReduction == 0 {
					ctrl.RiskReduction = v.DefaultRiskReduction
				}
			}
		}

		for _, asset := range tm.InformationAssets {
			if asset == nil || asset.Ref == "" {
				continue
			}
			item, ok := assetItems[asset.Ref]
			if !ok || item == nil || item.CurrentVersion == nil {
				continue
			}
			v := item.CurrentVersion
			if asset.Description == "" {
				asset.Description = v.Description
			}
			if asset.InformationClassification == "" {
				asset.InformationClassification = v.InformationClassification
			}
			if asset.Source == "" {
				asset.Source = v.Source
			}
			// Name (label) intentionally NOT overlaid — it is the join key
			// for threat.information_asset_refs and DFD data_store.information_asset.
		}
	}
}
