package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/threatcl/spec"
)

type CloudCreateCommand struct {
	*GlobalCmdOptions
	flagOrgId       string
	flagName        string
	flagDescription string
	flagUpload      string
	httpClient      HTTPClient
	keyringSvc      KeyringService
	fsSvc           FileSystemService
	specCfg         *spec.ThreatmodelSpecConfig
}

func (c *CloudCreateCommand) Help() string {
	helpText := `
Usage: threatcl cloud create -name=<name> [-description=<description>] [-upload=<file>] [-org-id=<orgId>]

	Create a new threat model in ThreatCL Cloud.

	The -name flag is required and will be the name of the new threat model.

	The -description flag is optional and provides a description for the threat model.

	The -upload flag is optional and allows uploading a threat model HCL file immediately
	after creating the threat model.

	If -org-id is not provided, the command will automatically use the
	first organization from your user profile.

Options:

 -name=<name>
   Required. The name of the threat model to create.

 -description=<description>
   Optional. A description for the threat model.

 -upload=<file>
   Optional. Path to an HCL file to upload immediately after creating the threat model.
   The file must contain exactly one threat model.

 -org-id=<orgId>
   Optional organization ID. If not provided, uses the first organization
   from your user profile.

 -config=<file>
   Optional config file

Environment Variables:

 THREATCL_API_URL
   Override the API base URL (default: https://api.threatcl.com)
   Example: THREATCL_API_URL=http://localhost:8080 threatcl cloud create -name="My Model"

`
	return strings.TrimSpace(helpText)
}

func (c *CloudCreateCommand) Synopsis() string {
	return "Create a new threat model in ThreatCL Cloud"
}

func (c *CloudCreateCommand) Run(args []string) int {
	flagSet := c.GetFlagset("cloud create")
	flagSet.StringVar(&c.flagOrgId, "org-id", "", "Organization ID (optional)")
	flagSet.StringVar(&c.flagName, "name", "", "Threat model name (required)")
	flagSet.StringVar(&c.flagDescription, "description", "", "Threat model description (optional)")
	flagSet.StringVar(&c.flagUpload, "upload", "", "HCL file to upload (optional)")
	flagSet.Parse(args)

	if c.flagName == "" {
		fmt.Fprintf(os.Stderr, "Error: -name is required\n")
		fmt.Fprintf(os.Stderr, "Run 'threatcl cloud create -help' for usage information.\n")
		return 1
	}

	// If upload flag is provided, validate the file exists and is parseable
	if c.flagUpload != "" {
		// Load config if provided
		if c.flagConfig != "" {
			err := c.specCfg.LoadSpecConfigFile(c.flagConfig)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading config file: %s\n", err)
				return 1
			}
		}

		// Validate and parse the HCL file
		tmParser := spec.NewThreatmodelParser(c.specCfg)
		err := tmParser.ParseFile(c.flagUpload, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing HCL file: %s\n", err)
			return 1
		}

		// Constraint check
		constraintMsg, err := spec.VersionConstraints(tmParser.GetWrapped(), false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error checking constraints: %s\n", err)
			return 1
		}
		if constraintMsg != "" {
			fmt.Fprintf(os.Stderr, "Warning: %s Found in %s\n", constraintMsg, c.flagUpload)
		}

		// Check that exactly one threat model exists
		tmCount := len(tmParser.GetWrapped().Threatmodels)
		if tmCount != 1 {
			fmt.Fprintf(os.Stderr, "Error: file must contain exactly one threat model, found %d\n", tmCount)
			return 1
		}
	}

	// Use injected dependencies or defaults
	httpClient := c.httpClient
	if httpClient == nil {
		timeout := 10 * time.Second
		// Use longer timeout if we're uploading a file
		if c.flagUpload != "" {
			timeout = 30 * time.Second
		}
		httpClient = &defaultHTTPClient{
			client: &http.Client{
				Timeout: timeout,
			},
		}
	}
	keyringSvc := c.keyringSvc
	if keyringSvc == nil {
		keyringSvc = &defaultKeyringService{}
	}
	fsSvc := c.fsSvc
	if fsSvc == nil {
		fsSvc = &defaultFileSystemService{}
	}

	// Step 1: Retrieve token
	token, err := getToken(keyringSvc, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving token: %s\n", err)
		fmt.Fprintf(os.Stderr, "Please run 'threatcl cloud login' to authenticate.\n")
		return 1
	}

	// Step 2: Get organization ID
	orgId := c.flagOrgId
	if orgId == "" {
		// Fetch user info to get first organization
		whoamiResp, err := c.fetchUserInfo(token, httpClient, fsSvc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching user information: %s\n", err)
			return 1
		}

		if len(whoamiResp.Organizations) == 0 {
			fmt.Fprintf(os.Stderr, "Error: No organizations found. Please specify an organization ID with -org-id\n")
			return 1
		}

		orgId = whoamiResp.Organizations[0].Organization.ID
	}

	// Step 3: Create the threat model
	threatModel, err := c.createThreatModel(token, orgId, c.flagName, c.flagDescription, httpClient, fsSvc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating threat model: %s\n", err)
		return 1
	}

	fmt.Printf("Successfully created threat model '%s'\n", threatModel.Name)
	fmt.Printf("  ID: %s\n", threatModel.ID)
	fmt.Printf("  Slug: %s\n", threatModel.Slug)
	if threatModel.Description != "" {
		fmt.Printf("  Description: %s\n", threatModel.Description)
	}

	// Step 4: Upload file if provided
	if c.flagUpload != "" {
		fmt.Printf("\nUploading file %s...\n", c.flagUpload)
		err := c.uploadFile(token, orgId, threatModel.Slug, c.flagUpload, httpClient, fsSvc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error uploading file: %s\n", err)
			fmt.Fprintf(os.Stderr, "Note: The threat model was created successfully, but the upload failed.\n")
			return 1
		}
		fmt.Printf("Successfully uploaded threat model from %s\n", c.flagUpload)
	}

	return 0
}

func (c *CloudCreateCommand) fetchUserInfo(token string, httpClient HTTPClient, fsSvc FileSystemService) (*whoamiResponse, error) {
	url := fmt.Sprintf("%s/api/v1/users/me", getAPIBaseURL(fsSvc))

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("authentication failed - token may be invalid or expired. Please run 'threatcl cloud login' again")
		}
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var whoamiResp whoamiResponse
	if err := json.NewDecoder(resp.Body).Decode(&whoamiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &whoamiResp, nil
}

func (c *CloudCreateCommand) createThreatModel(token string, orgId string, name string, description string, httpClient HTTPClient, fsSvc FileSystemService) (*threatModel, error) {
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

func (c *CloudCreateCommand) uploadFile(token string, orgId string, modelIdOrSlug string, filePath string, httpClient HTTPClient, fsSvc FileSystemService) error {
	url := fmt.Sprintf("%s/api/v1/org/%s/models/%s/upload", getAPIBaseURL(fsSvc), orgId, modelIdOrSlug)

	// Read the file
	fileData, err := fsSvc.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
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
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Send request
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("authentication failed - token may be invalid or expired. Please run 'threatcl cloud login' again")
		}
		if resp.StatusCode == http.StatusNotFound {
			return fmt.Errorf("threat model not found: %s", modelIdOrSlug)
		}
		return fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
