package main

import (
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

func tokenRemoveTestCommand(t testing.TB, k *mockKeyringService, f *mockFileSystemService) *CloudTokenRemoveCommand {
	t.Helper()

	return &CloudTokenRemoveCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: &GlobalCmdOptions{},
			httpClient:       newMockHTTPClient(),
			keyringSvc:       k,
			fsSvc:            f,
		},
	}
}

func TestCloudTokenRemoveRun(t *testing.T) {
	tests := []struct {
		name         string
		setup        func(t *testing.T, k *mockKeyringService)
		args         []string
		expectedCode int
		expectedOuts []string
		verify       func(t *testing.T, k *mockKeyringService, f *mockFileSystemService)
	}{
		{
			name:         "missing org id argument",
			setup:        func(t *testing.T, k *mockKeyringService) {},
			args:         []string{},
			expectedCode: 1,
			expectedOuts: []string{
				"organization ID is required",
				"Usage: threatcl cloud token remove <org-id>",
			},
		},
		{
			name: "org not found",
			setup: func(t *testing.T, k *mockKeyringService) {
				k.setMockToken("tok-1", "org-one", "Org One")
			},
			args:         []string{"missing-org"},
			expectedCode: 1,
			expectedOuts: []string{"no token found for organization missing-org"},
		},
		{
			name:         "no tokens stored",
			setup:        func(t *testing.T, k *mockKeyringService) {},
			args:         []string{"org-one"},
			expectedCode: 1,
			expectedOuts: []string{"no token found for organization org-one"},
		},
		{
			name: "remove token with org name",
			setup: func(t *testing.T, k *mockKeyringService) {
				k.setMockToken("tok-1", "org-one", "Org One")
			},
			args:         []string{"org-one"},
			expectedCode: 0,
			expectedOuts: []string{"Token removed for organization: Org One (org-one)"},
			verify: func(t *testing.T, k *mockKeyringService, f *mockFileSystemService) {
				tokens, _, err := listTokens(k, f)
				if err != nil {
					t.Fatalf("unexpected error listing tokens: %v", err)
				}
				if _, exists := tokens["org-one"]; exists {
					t.Error("expected org-one token to be removed from store")
				}
			},
		},
		{
			name: "remove token without org name",
			setup: func(t *testing.T, k *mockKeyringService) {
				tokenCmdTestSeedStore(t, k, "org-one", []tokenCmdTestOrg{
					{id: "org-one", name: ""},
				})
			},
			args:         []string{"org-one"},
			expectedCode: 0,
			expectedOuts: []string{"Token removed for organization: org-one\n"},
		},
		{
			name: "removing default of two promotes remaining org",
			setup: func(t *testing.T, k *mockKeyringService) {
				tokenCmdTestSeedStore(t, k, "org-one", []tokenCmdTestOrg{
					{id: "org-one", name: "Org One"},
					{id: "org-two", name: "Org Two"},
				})
			},
			args:         []string{"org-one"},
			expectedCode: 0,
			expectedOuts: []string{"Token removed for organization: Org One (org-one)"},
			verify: func(t *testing.T, k *mockKeyringService, f *mockFileSystemService) {
				tokens, defaultOrg, err := listTokens(k, f)
				if err != nil {
					t.Fatalf("unexpected error listing tokens: %v", err)
				}
				if len(tokens) != 1 {
					t.Errorf("expected 1 remaining token, got %d", len(tokens))
				}
				if defaultOrg != "org-two" {
					t.Errorf("expected default org to become org-two, got %q", defaultOrg)
				}
			},
		},
		{
			name: "removing default of three clears default",
			setup: func(t *testing.T, k *mockKeyringService) {
				tokenCmdTestSeedStore(t, k, "org-one", []tokenCmdTestOrg{
					{id: "org-one", name: "Org One"},
					{id: "org-two", name: "Org Two"},
					{id: "org-three", name: "Org Three"},
				})
			},
			args:         []string{"org-one"},
			expectedCode: 0,
			expectedOuts: []string{"Token removed for organization: Org One (org-one)"},
			verify: func(t *testing.T, k *mockKeyringService, f *mockFileSystemService) {
				tokens, defaultOrg, err := listTokens(k, f)
				if err != nil {
					t.Fatalf("unexpected error listing tokens: %v", err)
				}
				if len(tokens) != 2 {
					t.Errorf("expected 2 remaining tokens, got %d", len(tokens))
				}
				if defaultOrg != "" {
					t.Errorf("expected default org to be cleared, got %q", defaultOrg)
				}
			},
		},
		{
			name: "removing non-default keeps default",
			setup: func(t *testing.T, k *mockKeyringService) {
				tokenCmdTestSeedStore(t, k, "org-one", []tokenCmdTestOrg{
					{id: "org-one", name: "Org One"},
					{id: "org-two", name: "Org Two"},
				})
			},
			args:         []string{"org-two"},
			expectedCode: 0,
			expectedOuts: []string{"Token removed for organization: Org Two (org-two)"},
			verify: func(t *testing.T, k *mockKeyringService, f *mockFileSystemService) {
				_, defaultOrg, err := listTokens(k, f)
				if err != nil {
					t.Fatalf("unexpected error listing tokens: %v", err)
				}
				if defaultOrg != "org-one" {
					t.Errorf("expected default org to remain org-one, got %q", defaultOrg)
				}
			},
		},
		{
			name:         "old token format returns error",
			setup:        func(t *testing.T, k *mockKeyringService) { tokenCmdTestSeedOldFormat(t, k) },
			args:         []string{"org-one"},
			expectedCode: 1,
			expectedOuts: []string{"Error retrieving tokens", "token format has changed"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()
			tt.setup(t, keyringSvc)

			cmd := tokenRemoveTestCommand(t, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run(tt.args)
			})

			if code != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d", tt.expectedCode, code)
			}

			for _, want := range tt.expectedOuts {
				if !strings.Contains(out, want) {
					t.Errorf("expected output to contain %q, got %q", want, out)
				}
			}

			if tt.verify != nil {
				tt.verify(t, keyringSvc, fsSvc)
			}
		})
	}
}

func TestCloudTokenRemoveHelpAndSynopsis(t *testing.T) {
	cmd := &CloudTokenRemoveCommand{}

	if !strings.Contains(cmd.Help(), "threatcl cloud token remove <org-id>") {
		t.Errorf("expected help to contain usage line, got %q", cmd.Help())
	}
	if cmd.Synopsis() == "" {
		t.Error("expected non-empty synopsis")
	}
}
