package main

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/threatcl/spec"
	"github.com/zenizh/go-capturer"
)

func TestCloudViewHelp(t *testing.T) {
	cmd := &CloudViewCommand{}
	help := cmd.Help()

	if !strings.Contains(help, "threatcl cloud view") {
		t.Error("Help text should contain command name")
	}

	if !strings.Contains(help, "-raw") {
		t.Error("Help text should mention -raw flag")
	}
}

func TestCloudViewSynopsis(t *testing.T) {
	cmd := &CloudViewCommand{}
	synopsis := cmd.Synopsis()

	if synopsis == "" {
		t.Error("Synopsis should not be empty")
	}

	if !strings.Contains(strings.ToLower(synopsis), "view") {
		t.Error("Synopsis should mention view")
	}
}

func TestCloudViewRun(t *testing.T) {
	validHCL := `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "A test threat model"
}
`

	validHCLWithControlRefs := `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "A test threat model"

  threat "Test Threat" {
    description = "A threat"

    control "Test Control" {
      ref = "CTRL-001"
      description = ""
    }
  }
}
`

	tests := []struct {
		name         string
		fileContent  string
		createFile   bool
		token        string
		statusCode   int
		response     string
		graphQLResp  string
		expectedCode int
		expectedOut  string
		useRaw       bool
	}{
		{
			name:         "no file provided",
			expectedCode: 1,
			expectedOut:  "either -model-id or a file path is required",
		},
		{
			name:         "file does not exist",
			createFile:   false,
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "does not exist",
		},
		{
			name:        "successful view without control refs",
			fileContent: validHCL,
			createFile:  true,
			token:       "valid-token",
			statusCode:  http.StatusOK,
			response: jsonResponse(whoamiResponse{
				User: userInfo{Email: "test@example.com", FullName: "Test User"},
				Organizations: []orgMembership{
					{
						Organization: orgInfo{
							ID:   "org-id",
							Name: "Test Org",
							Slug: "test-org",
						},
						Role: "admin",
					},
				},
			}),
			expectedCode: 0,
			expectedOut:  "Test Model",
			useRaw:       true,
		},
		{
			name:        "successful view with control enrichment",
			fileContent: validHCLWithControlRefs,
			createFile:  true,
			token:       "valid-token",
			statusCode:  http.StatusOK,
			response: jsonResponse(whoamiResponse{
				User: userInfo{Email: "test@example.com", FullName: "Test User"},
				Organizations: []orgMembership{
					{
						Organization: orgInfo{
							ID:   "org-id",
							Name: "Test Org",
							Slug: "test-org",
						},
						Role: "admin",
					},
				},
			}),
			graphQLResp: `{
				"data": {
					"controlLibraryItemsByRefs": [{
						"id": "ctrl-1",
						"referenceId": "CTRL-001",
						"name": "Control from Library",
						"status": "PUBLISHED",
						"currentVersion": {
							"version": "1.0",
							"name": "Control from Library",
							"description": "Description from cloud",
							"implementationGuidance": "Do this thing",
							"defaultRiskReduction": 50
						}
					}]
				}
			}`,
			expectedCode: 0,
			expectedOut:  "Description from cloud",
			useRaw:       true,
		},
		{
			name:        "view with missing control refs shows warning",
			fileContent: validHCLWithControlRefs,
			createFile:  true,
			token:       "valid-token",
			statusCode:  http.StatusOK,
			response: jsonResponse(whoamiResponse{
				User: userInfo{Email: "test@example.com", FullName: "Test User"},
				Organizations: []orgMembership{
					{
						Organization: orgInfo{
							ID:   "org-id",
							Name: "Test Org",
							Slug: "test-org",
						},
						Role: "admin",
					},
				},
			}),
			graphQLResp: `{
				"data": {
					"controlLibraryItemsByRefs": []
				}
			}`,
			expectedCode: 0,
			expectedOut:  "unknown control refs",
			useRaw:       true,
		},
		{
			name:         "missing token",
			fileContent:  validHCL,
			createFile:   true,
			token:        "",
			expectedCode: 1,
			expectedOut:  "no tokens found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var filePath string

			// Create temporary file if needed
			if tt.createFile {
				tmpFile, err := os.CreateTemp("", "test-*.hcl")
				if err != nil {
					t.Fatalf("failed to create temp file: %v", err)
				}
				defer os.Remove(tmpFile.Name())
				filePath = tmpFile.Name()

				if tt.fileContent != "" {
					if _, err := tmpFile.Write([]byte(tt.fileContent)); err != nil {
						t.Fatalf("failed to write temp file: %v", err)
					}
					tmpFile.Close()
				} else {
					tmpFile.Close()
				}
			} else if tt.name == "file does not exist" {
				filePath = "nonexistent-file.hcl"
			}

			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			// Set up token in new format
			if tt.token != "" {
				keyringSvc.setMockToken(tt.token, "test-org-id", "Test Org")
			}

			// Set up HTTP response
			if tt.statusCode != 0 {
				httpClient.transport.setResponse("GET", "/api/v1/users/me", tt.statusCode, tt.response)
			}

			// Set up GraphQL response for control refs
			if tt.graphQLResp != "" {
				httpClient.transport.setResponse("POST", "/api/v1/graphql", http.StatusOK, tt.graphQLResp)
			}

			cfg, err := spec.LoadSpecConfig()
			if err != nil {
				t.Fatalf("failed to load spec config: %v", err)
			}

			cmd := &CloudViewCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: &GlobalCmdOptions{},
					httpClient:       httpClient,
					keyringSvc:       keyringSvc,
					fsSvc:            fsSvc,
				},
				specCfg: cfg,
				testEnv: true,
			}

			var args []string
			if tt.name == "no file provided" {
				args = []string{}
			} else {
				if tt.useRaw {
					args = []string{"-raw", filePath}
				} else {
					args = []string{filePath}
				}
			}

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run(args)
			})

			if code != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d\nOutput: %s", tt.expectedCode, code, out)
			}

			if tt.expectedOut != "" && !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}
		})
	}
}

func TestEnrichControlsWithCloudData(t *testing.T) {
	tests := []struct {
		name            string
		wrapped         *spec.ThreatmodelWrapped
		cloudControls   map[string]*controlLibraryItem
		expectedDesc    string
		expectedRisk    int
		expectedNotes   string
		expectedName    string
		expectedSkipped int
		controlIdx      int
	}{
		{
			name: "enrich empty control fields from PUBLISHED control",
			wrapped: &spec.ThreatmodelWrapped{
				Threatmodels: []spec.Threatmodel{
					{
						Name:   "Test TM",
						Author: "test",
						Threats: []*spec.Threat{
							{
								Name:        "Threat 1",
								Description: "desc",
								Controls: []*spec.Control{
									{
										Name:        "",
										Ref:         "CTRL-001",
										Description: "",
									},
								},
							},
						},
					},
				},
			},
			cloudControls: map[string]*controlLibraryItem{
				"CTRL-001": {
					ReferenceID: "CTRL-001",
					Name:        "Cloud Control 1",
					Status:      "PUBLISHED",
					CurrentVersion: &controlLibraryVersion{
						Name:                   "Cloud Control 1",
						Description:            "Cloud description",
						ImplementationGuidance: "Cloud guidance",
						DefaultRiskReduction:   75,
					},
				},
			},
			expectedDesc:    "Cloud description",
			expectedRisk:    75,
			expectedNotes:   "Cloud guidance",
			expectedName:    "Cloud Control 1",
			expectedSkipped: 0,
			controlIdx:      0,
		},
		{
			name: "name is overridden but other local values preserved",
			wrapped: &spec.ThreatmodelWrapped{
				Threatmodels: []spec.Threatmodel{
					{
						Name:   "Test TM",
						Author: "test",
						Threats: []*spec.Threat{
							{
								Name:        "Threat 1",
								Description: "desc",
								Controls: []*spec.Control{
									{
										Name:                "Local Name",
										Ref:                 "CTRL-002",
										Description:         "Local description",
										RiskReduction:       25,
										ImplementationNotes: "Local notes",
									},
								},
							},
						},
					},
				},
			},
			cloudControls: map[string]*controlLibraryItem{
				"CTRL-002": {
					ReferenceID: "CTRL-002",
					Name:        "Cloud Control 2",
					Status:      "PUBLISHED",
					CurrentVersion: &controlLibraryVersion{
						Name:                   "Cloud Control 2",
						Description:            "Cloud description 2",
						ImplementationGuidance: "Cloud guidance 2",
						DefaultRiskReduction:   80,
					},
				},
			},
			expectedDesc:    "Local description",
			expectedRisk:    25,
			expectedNotes:   "Local notes",
			expectedName:    "Cloud Control 2", // Name is always overridden by cloud
			expectedSkipped: 0,
			controlIdx:      0,
		},
		{
			name: "control without ref is skipped",
			wrapped: &spec.ThreatmodelWrapped{
				Threatmodels: []spec.Threatmodel{
					{
						Name:   "Test TM",
						Author: "test",
						Threats: []*spec.Threat{
							{
								Name:        "Threat 1",
								Description: "desc",
								Controls: []*spec.Control{
									{
										Name:        "No Ref Control",
										Ref:         "",
										Description: "Original desc",
									},
								},
							},
						},
					},
				},
			},
			cloudControls: map[string]*controlLibraryItem{
				"CTRL-003": {
					ReferenceID: "CTRL-003",
					Name:        "Cloud Control 3",
					Status:      "PUBLISHED",
					CurrentVersion: &controlLibraryVersion{
						Description: "Cloud description 3",
					},
				},
			},
			expectedDesc:    "Original desc",
			expectedName:    "No Ref Control",
			expectedSkipped: 0,
			controlIdx:      0,
		},
		{
			name: "control ref not in cloud map",
			wrapped: &spec.ThreatmodelWrapped{
				Threatmodels: []spec.Threatmodel{
					{
						Name:   "Test TM",
						Author: "test",
						Threats: []*spec.Threat{
							{
								Name:        "Threat 1",
								Description: "desc",
								Controls: []*spec.Control{
									{
										Name:        "Unknown Ref",
										Ref:         "UNKNOWN-REF",
										Description: "Original desc",
									},
								},
							},
						},
					},
				},
			},
			cloudControls:   map[string]*controlLibraryItem{},
			expectedDesc:    "Original desc",
			expectedName:    "Unknown Ref",
			expectedSkipped: 0,
			controlIdx:      0,
		},
		{
			name: "DRAFT control is skipped",
			wrapped: &spec.ThreatmodelWrapped{
				Threatmodels: []spec.Threatmodel{
					{
						Name:   "Test TM",
						Author: "test",
						Threats: []*spec.Threat{
							{
								Name:        "Threat 1",
								Description: "desc",
								Controls: []*spec.Control{
									{
										Name:        "Draft Control",
										Ref:         "CTRL-DRAFT",
										Description: "Original desc",
									},
								},
							},
						},
					},
				},
			},
			cloudControls: map[string]*controlLibraryItem{
				"CTRL-DRAFT": {
					ReferenceID: "CTRL-DRAFT",
					Name:        "Draft Cloud Control",
					Status:      "DRAFT",
					CurrentVersion: &controlLibraryVersion{
						Name:        "Draft Cloud Control",
						Description: "Should not be used",
					},
				},
			},
			expectedDesc:    "Original desc",
			expectedName:    "Draft Control", // Not overridden because DRAFT
			expectedSkipped: 1,
			controlIdx:      0,
		},
		{
			name: "ARCHIVED control is skipped",
			wrapped: &spec.ThreatmodelWrapped{
				Threatmodels: []spec.Threatmodel{
					{
						Name:   "Test TM",
						Author: "test",
						Threats: []*spec.Threat{
							{
								Name:        "Threat 1",
								Description: "desc",
								Controls: []*spec.Control{
									{
										Name:        "Archived Control",
										Ref:         "CTRL-ARCHIVED",
										Description: "Original desc",
									},
								},
							},
						},
					},
				},
			},
			cloudControls: map[string]*controlLibraryItem{
				"CTRL-ARCHIVED": {
					ReferenceID: "CTRL-ARCHIVED",
					Name:        "Archived Cloud Control",
					Status:      "ARCHIVED",
					CurrentVersion: &controlLibraryVersion{
						Name:        "Archived Cloud Control",
						Description: "Should not be used",
					},
				},
			},
			expectedDesc:    "Original desc",
			expectedName:    "Archived Control", // Not overridden because ARCHIVED
			expectedSkipped: 1,
			controlIdx:      0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skipped := enrichControlsWithCloudData(tt.wrapped, tt.cloudControls)

			if len(skipped) != tt.expectedSkipped {
				t.Errorf("expected %d skipped controls, got %d", tt.expectedSkipped, len(skipped))
			}

			control := tt.wrapped.Threatmodels[0].Threats[0].Controls[tt.controlIdx]

			if tt.expectedName != "" && control.Name != tt.expectedName {
				t.Errorf("expected Name %q, got %q", tt.expectedName, control.Name)
			}

			if tt.expectedDesc != "" && control.Description != tt.expectedDesc {
				t.Errorf("expected Description %q, got %q", tt.expectedDesc, control.Description)
			}

			if tt.expectedRisk != 0 && control.RiskReduction != tt.expectedRisk {
				t.Errorf("expected RiskReduction %d, got %d", tt.expectedRisk, control.RiskReduction)
			}

			if tt.expectedNotes != "" && !strings.Contains(control.ImplementationNotes, tt.expectedNotes) {
				t.Errorf("expected ImplementationNotes to contain %q, got %q", tt.expectedNotes, control.ImplementationNotes)
			}
		})
	}
}

func TestEnrichControlsWithCloudDataNilInputs(t *testing.T) {
	// Test nil wrapped
	skipped := enrichControlsWithCloudData(nil, map[string]*controlLibraryItem{})
	if len(skipped) != 0 {
		t.Errorf("expected 0 skipped for nil wrapped, got %d", len(skipped))
	}

	// Test nil cloudControls
	wrapped := &spec.ThreatmodelWrapped{
		Threatmodels: []spec.Threatmodel{
			{
				Name:   "Test",
				Author: "test",
			},
		},
	}
	skipped = enrichControlsWithCloudData(wrapped, nil)
	if len(skipped) != 0 {
		t.Errorf("expected 0 skipped for nil cloudControls, got %d", len(skipped))
	}

	// Should not panic
}

func TestCloudViewWithConfig(t *testing.T) {
	validHCL := `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
}

threatmodel "Test Model" {
  author = "test@example.com"
  description = "Test"
}
`

	tests := []struct {
		name         string
		configFile   string
		configExists bool
		expectedCode int
		expectedOut  string
	}{
		{
			name: "valid config file",
			configFile: `
initiative_sizes = ["Small", "Medium", "Large"]
default_initiative_size = "Medium"
`,
			configExists: true,
			expectedCode: 0,
			expectedOut:  "Test Model",
		},
		{
			name:         "config file does not exist",
			configFile:   "",
			configExists: false,
			expectedCode: 1,
			expectedOut:  "Error loading config file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "test-*.hcl")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())

			if _, err := tmpFile.Write([]byte(validHCL)); err != nil {
				t.Fatalf("failed to write temp file: %v", err)
			}
			tmpFile.Close()

			var configPath string
			if tt.configExists {
				configFile, err := os.CreateTemp("", "config-*.hcl")
				if err != nil {
					t.Fatalf("failed to create config file: %v", err)
				}
				defer os.Remove(configFile.Name())
				configPath = configFile.Name()

				if _, err := configFile.Write([]byte(tt.configFile)); err != nil {
					t.Fatalf("failed to write config file: %v", err)
				}
				configFile.Close()
			} else {
				configPath = "/nonexistent/config.hcl"
			}

			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			keyringSvc.setMockToken("valid-token", "test-org-id", "Test Org")

			httpClient.transport.setResponse("GET", "/api/v1/users/me", http.StatusOK, jsonResponse(whoamiResponse{
				User: userInfo{Email: "test@example.com", FullName: "Test User"},
				Organizations: []orgMembership{
					{
						Organization: orgInfo{
							ID:   "org-id",
							Name: "Test Org",
							Slug: "test-org",
						},
						Role: "admin",
					},
				},
			}))

			cfg, err := spec.LoadSpecConfig()
			if err != nil {
				t.Fatalf("failed to load spec config: %v", err)
			}

			cmd := &CloudViewCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: &GlobalCmdOptions{},
					httpClient:       httpClient,
					keyringSvc:       keyringSvc,
					fsSvc:            fsSvc,
				},
				specCfg: cfg,
				testEnv: true,
			}

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run([]string{"-config", configPath, "-raw", tmpFile.Name()})
			})

			if code != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d\nOutput: %s", tt.expectedCode, code, out)
			}

			if tt.expectedOut != "" && !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}
		})
	}
}

func TestEnrichThreatsWithCloudData(t *testing.T) {
	tests := []struct {
		name            string
		wrapped         *spec.ThreatmodelWrapped
		cloudThreats    map[string]*threatLibraryItem
		expectedDesc    string
		expectedName    string
		expectedImpacts []string
		expectedStride  []string
		expectedSkipped int
		threatIdx       int
	}{
		{
			name: "enrich empty threat fields from PUBLISHED threat",
			wrapped: &spec.ThreatmodelWrapped{
				Threatmodels: []spec.Threatmodel{
					{
						Name:   "Test TM",
						Author: "test",
						Threats: []*spec.Threat{
							{
								Name:        "",
								Ref:         "THR-001",
								Description: "",
							},
						},
					},
				},
			},
			cloudThreats: map[string]*threatLibraryItem{
				"THR-001": {
					ReferenceID: "THR-001",
					Name:        "Cloud Threat 1",
					Status:      "PUBLISHED",
					CurrentVersion: &threatLibraryVersion{
						Name:        "Cloud Threat 1",
						Description: "Cloud threat description",
						Impacts:     []string{"Confidentiality", "Integrity"},
						Stride:      []string{"Spoofing", "Tampering"},
					},
				},
			},
			expectedDesc:    "Cloud threat description",
			expectedName:    "Cloud Threat 1",
			expectedImpacts: []string{"Confidentiality", "Integrity"},
			expectedStride:  []string{"Spoofing", "Tampering"},
			expectedSkipped: 0,
			threatIdx:       0,
		},
		{
			name: "name is overridden but other local values preserved",
			wrapped: &spec.ThreatmodelWrapped{
				Threatmodels: []spec.Threatmodel{
					{
						Name:   "Test TM",
						Author: "test",
						Threats: []*spec.Threat{
							{
								Name:        "Local Threat Name",
								Ref:         "THR-002",
								Description: "Local description",
								ImpactType:  []string{"Availability"},
								Stride:      []string{"Denial of Service"},
							},
						},
					},
				},
			},
			cloudThreats: map[string]*threatLibraryItem{
				"THR-002": {
					ReferenceID: "THR-002",
					Name:        "Cloud Threat 2",
					Status:      "PUBLISHED",
					CurrentVersion: &threatLibraryVersion{
						Name:        "Cloud Threat 2",
						Description: "Cloud description 2",
						Impacts:     []string{"Confidentiality"},
						Stride:      []string{"Information Disclosure"},
					},
				},
			},
			expectedDesc:    "Local description",
			expectedName:    "Cloud Threat 2", // Name is always overridden by cloud
			expectedImpacts: []string{"Availability"},
			expectedStride:  []string{"Denial of Service"},
			expectedSkipped: 0,
			threatIdx:       0,
		},
		{
			name: "threat without ref is skipped",
			wrapped: &spec.ThreatmodelWrapped{
				Threatmodels: []spec.Threatmodel{
					{
						Name:   "Test TM",
						Author: "test",
						Threats: []*spec.Threat{
							{
								Name:        "No Ref Threat",
								Ref:         "",
								Description: "Original desc",
							},
						},
					},
				},
			},
			cloudThreats: map[string]*threatLibraryItem{
				"THR-003": {
					ReferenceID: "THR-003",
					Name:        "Cloud Threat 3",
					Status:      "PUBLISHED",
					CurrentVersion: &threatLibraryVersion{
						Description: "Cloud description 3",
					},
				},
			},
			expectedDesc:    "Original desc",
			expectedName:    "No Ref Threat",
			expectedSkipped: 0,
			threatIdx:       0,
		},
		{
			name: "threat ref not in cloud map",
			wrapped: &spec.ThreatmodelWrapped{
				Threatmodels: []spec.Threatmodel{
					{
						Name:   "Test TM",
						Author: "test",
						Threats: []*spec.Threat{
							{
								Name:        "Unknown Ref",
								Ref:         "UNKNOWN-REF",
								Description: "Original desc",
							},
						},
					},
				},
			},
			cloudThreats:    map[string]*threatLibraryItem{},
			expectedDesc:    "Original desc",
			expectedName:    "Unknown Ref",
			expectedSkipped: 0,
			threatIdx:       0,
		},
		{
			name: "DRAFT threat is skipped",
			wrapped: &spec.ThreatmodelWrapped{
				Threatmodels: []spec.Threatmodel{
					{
						Name:   "Test TM",
						Author: "test",
						Threats: []*spec.Threat{
							{
								Name:        "Draft Threat",
								Ref:         "THR-DRAFT",
								Description: "Original desc",
							},
						},
					},
				},
			},
			cloudThreats: map[string]*threatLibraryItem{
				"THR-DRAFT": {
					ReferenceID: "THR-DRAFT",
					Name:        "Draft Cloud Threat",
					Status:      "DRAFT",
					CurrentVersion: &threatLibraryVersion{
						Name:        "Draft Cloud Threat",
						Description: "Should not be used",
					},
				},
			},
			expectedDesc:    "Original desc",
			expectedName:    "Draft Threat", // Not overridden because DRAFT
			expectedSkipped: 1,
			threatIdx:       0,
		},
		{
			name: "ARCHIVED threat is skipped",
			wrapped: &spec.ThreatmodelWrapped{
				Threatmodels: []spec.Threatmodel{
					{
						Name:   "Test TM",
						Author: "test",
						Threats: []*spec.Threat{
							{
								Name:        "Archived Threat",
								Ref:         "THR-ARCHIVED",
								Description: "Original desc",
							},
						},
					},
				},
			},
			cloudThreats: map[string]*threatLibraryItem{
				"THR-ARCHIVED": {
					ReferenceID: "THR-ARCHIVED",
					Name:        "Archived Cloud Threat",
					Status:      "ARCHIVED",
					CurrentVersion: &threatLibraryVersion{
						Name:        "Archived Cloud Threat",
						Description: "Should not be used",
					},
				},
			},
			expectedDesc:    "Original desc",
			expectedName:    "Archived Threat", // Not overridden because ARCHIVED
			expectedSkipped: 1,
			threatIdx:       0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skipped := enrichThreatsWithCloudData(tt.wrapped, tt.cloudThreats)

			if len(skipped) != tt.expectedSkipped {
				t.Errorf("expected %d skipped threats, got %d", tt.expectedSkipped, len(skipped))
			}

			threat := tt.wrapped.Threatmodels[0].Threats[tt.threatIdx]

			if tt.expectedName != "" && threat.Name != tt.expectedName {
				t.Errorf("expected Name %q, got %q", tt.expectedName, threat.Name)
			}

			if tt.expectedDesc != "" && threat.Description != tt.expectedDesc {
				t.Errorf("expected Description %q, got %q", tt.expectedDesc, threat.Description)
			}

			if tt.expectedImpacts != nil {
				if len(threat.ImpactType) != len(tt.expectedImpacts) {
					t.Errorf("expected %d impacts, got %d", len(tt.expectedImpacts), len(threat.ImpactType))
				} else {
					for i, impact := range tt.expectedImpacts {
						if threat.ImpactType[i] != impact {
							t.Errorf("expected impact[%d]=%q, got %q", i, impact, threat.ImpactType[i])
						}
					}
				}
			}

			if tt.expectedStride != nil {
				if len(threat.Stride) != len(tt.expectedStride) {
					t.Errorf("expected %d stride, got %d", len(tt.expectedStride), len(threat.Stride))
				} else {
					for i, stride := range tt.expectedStride {
						if threat.Stride[i] != stride {
							t.Errorf("expected stride[%d]=%q, got %q", i, stride, threat.Stride[i])
						}
					}
				}
			}
		})
	}
}

func TestEnrichThreatsWithCloudDataNilInputs(t *testing.T) {
	// Test nil wrapped
	skipped := enrichThreatsWithCloudData(nil, map[string]*threatLibraryItem{})
	if len(skipped) != 0 {
		t.Errorf("expected 0 skipped for nil wrapped, got %d", len(skipped))
	}

	// Test nil cloudThreats
	wrapped := &spec.ThreatmodelWrapped{
		Threatmodels: []spec.Threatmodel{
			{
				Name:   "Test",
				Author: "test",
			},
		},
	}
	skipped = enrichThreatsWithCloudData(wrapped, nil)
	if len(skipped) != 0 {
		t.Errorf("expected 0 skipped for nil cloudThreats, got %d", len(skipped))
	}

	// Should not panic
}

func TestCloudViewHelpModelId(t *testing.T) {
	cmd := &CloudViewCommand{}
	help := cmd.Help()

	if !strings.Contains(help, "-model-id") {
		t.Error("Help text should mention -model-id flag")
	}

	if !strings.Contains(help, "-org-id") {
		t.Error("Help text should mention -org-id flag")
	}

	if !strings.Contains(help, "[<file>]") {
		t.Error("Help text should show file as optional")
	}
}

func TestCloudViewModelId(t *testing.T) {
	validHCL := `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
}

threatmodel "Cloud Model" {
  author = "test@example.com"
  description = "A cloud threat model"
}
`

	validHCLWithControlRefs := `
spec_version = "0.1.10"

backend "threatcl-cloud" {
  organization = "test-org"
}

threatmodel "Cloud Model" {
  author = "test@example.com"
  description = "A cloud threat model"

  threat "Test Threat" {
    description = "A threat"

    control "Test Control" {
      ref = "CTRL-001"
      description = ""
    }
  }
}
`

	tests := []struct {
		name         string
		modelId      string
		orgId        string
		dlStatusCode int
		dlResponse   string
		meStatusCode int
		meResponse   string
		graphQLResp  string
		token        string
		expectedCode int
		expectedOut  string
		useRaw       bool
		fileArg      string
	}{
		{
			name:         "successful download and view",
			modelId:      "my-model",
			dlStatusCode: http.StatusOK,
			dlResponse:   validHCL,
			meStatusCode: http.StatusOK,
			meResponse: jsonResponse(whoamiResponse{
				User: userInfo{Email: "test@example.com", FullName: "Test User"},
				Organizations: []orgMembership{
					{
						Organization: orgInfo{
							ID:   "org-id",
							Name: "Test Org",
							Slug: "test-org",
						},
						Role: "admin",
					},
				},
			}),
			token:        "valid-token",
			expectedCode: 0,
			expectedOut:  "Cloud Model",
			useRaw:       true,
		},
		{
			name:         "successful download with control enrichment",
			modelId:      "my-model",
			dlStatusCode: http.StatusOK,
			dlResponse:   validHCLWithControlRefs,
			meStatusCode: http.StatusOK,
			meResponse: jsonResponse(whoamiResponse{
				User: userInfo{Email: "test@example.com", FullName: "Test User"},
				Organizations: []orgMembership{
					{
						Organization: orgInfo{
							ID:   "org-id",
							Name: "Test Org",
							Slug: "test-org",
						},
						Role: "admin",
					},
				},
			}),
			graphQLResp: `{
				"data": {
					"controlLibraryItemsByRefs": [{
						"id": "ctrl-1",
						"referenceId": "CTRL-001",
						"name": "Control from Library",
						"status": "PUBLISHED",
						"currentVersion": {
							"version": "1.0",
							"name": "Control from Library",
							"description": "Description from cloud",
							"implementationGuidance": "Do this thing",
							"defaultRiskReduction": 50
						}
					}]
				}
			}`,
			token:        "valid-token",
			expectedCode: 0,
			expectedOut:  "Description from cloud",
			useRaw:       true,
		},
		{
			name:         "download API error (not found)",
			modelId:      "nonexistent-model",
			dlStatusCode: http.StatusNotFound,
			dlResponse:   `{"error":"not found"}`,
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "Error downloading threat model",
		},
		{
			name:         "download API error (unauthorized)",
			modelId:      "my-model",
			dlStatusCode: http.StatusUnauthorized,
			dlResponse:   `{"error":"unauthorized"}`,
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "Error downloading threat model",
		},
		{
			name:         "model-id with org-id override",
			modelId:      "my-model",
			orgId:        "custom-org-id",
			dlStatusCode: http.StatusOK,
			dlResponse:   validHCL,
			meStatusCode: http.StatusOK,
			meResponse: jsonResponse(whoamiResponse{
				User: userInfo{Email: "test@example.com", FullName: "Test User"},
				Organizations: []orgMembership{
					{
						Organization: orgInfo{
							ID:   "custom-org-id",
							Name: "Custom Org",
							Slug: "test-org",
						},
						Role: "admin",
					},
				},
			}),
			token:        "valid-token",
			expectedCode: 0,
			expectedOut:  "Cloud Model",
			useRaw:       true,
		},
		{
			name:         "both file and model-id provided",
			modelId:      "my-model",
			fileArg:      "some-file.hcl",
			token:        "valid-token",
			expectedCode: 1,
			expectedOut:  "cannot specify both -model-id and a file argument",
		},
		{
			name:         "missing token with model-id",
			modelId:      "my-model",
			token:        "",
			expectedCode: 1,
			expectedOut:  "no tokens found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient := newMockHTTPClient()
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()

			if tt.token != "" {
				if tt.orgId != "" {
					keyringSvc.setMockToken(tt.token, tt.orgId, "Custom Org")
				} else {
					keyringSvc.setMockToken(tt.token, "test-org-id", "Test Org")
				}
			}

			// Set up download response
			if tt.dlStatusCode != 0 {
				orgIdForURL := "test-org-id"
				if tt.orgId != "" {
					orgIdForURL = tt.orgId
				}
				downloadPath := "/api/v1/org/" + orgIdForURL + "/models/" + tt.modelId + "/download"
				httpClient.transport.setResponse("GET", downloadPath, tt.dlStatusCode, tt.dlResponse)
			}

			// Set up /users/me response
			if tt.meStatusCode != 0 {
				httpClient.transport.setResponse("GET", "/api/v1/users/me", tt.meStatusCode, tt.meResponse)
			}

			// Set up GraphQL response for control refs
			if tt.graphQLResp != "" {
				httpClient.transport.setResponse("POST", "/api/v1/graphql", http.StatusOK, tt.graphQLResp)
			}

			cfg, err := spec.LoadSpecConfig()
			if err != nil {
				t.Fatalf("failed to load spec config: %v", err)
			}

			cmd := &CloudViewCommand{
				CloudCommandBase: CloudCommandBase{
					GlobalCmdOptions: &GlobalCmdOptions{},
					httpClient:       httpClient,
					keyringSvc:       keyringSvc,
					fsSvc:            fsSvc,
				},
				specCfg: cfg,
				testEnv: true,
			}

			var args []string
			if tt.modelId != "" {
				args = append(args, "-model-id", tt.modelId)
			}
			if tt.orgId != "" {
				args = append(args, "-org-id", tt.orgId)
			}
			if tt.useRaw {
				args = append(args, "-raw")
			}
			if tt.fileArg != "" {
				args = append(args, tt.fileArg)
			}

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run(args)
			})

			if code != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d\nOutput: %s", tt.expectedCode, code, out)
			}

			if tt.expectedOut != "" && !strings.Contains(out, tt.expectedOut) {
				t.Errorf("expected output to contain %q, got %q", tt.expectedOut, out)
			}
		})
	}
}
