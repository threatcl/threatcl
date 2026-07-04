package main

import (
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

func tokenDefaultTestCommand(t testing.TB, k *mockKeyringService, f *mockFileSystemService) *CloudTokenDefaultCommand {
	t.Helper()

	return &CloudTokenDefaultCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: &GlobalCmdOptions{},
			httpClient:       newMockHTTPClient(),
			keyringSvc:       k,
			fsSvc:            f,
		},
	}
}

func TestCloudTokenDefaultShow(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(t *testing.T, k *mockKeyringService)
		expectedCode  int
		expectedOuts  []string
		unexpectedOut string
	}{
		{
			name:         "no tokens stored",
			setup:        func(t *testing.T, k *mockKeyringService) {},
			expectedCode: 0,
			expectedOuts: []string{"No tokens stored", "threatcl cloud login"},
		},
		{
			name: "explicit default with org name",
			setup: func(t *testing.T, k *mockKeyringService) {
				k.setMockToken("tok-1", "org-one", "Org One")
			},
			expectedCode: 0,
			expectedOuts: []string{"Default organization: Org One (org-one)"},
		},
		{
			name: "explicit default without org name",
			setup: func(t *testing.T, k *mockKeyringService) {
				tokenCmdTestSeedStore(t, k, "org-one", []tokenCmdTestOrg{
					{id: "org-one", name: ""},
				})
			},
			expectedCode: 0,
			expectedOuts: []string{"Default organization: org-one\n"},
		},
		{
			name: "single token is implicit default",
			setup: func(t *testing.T, k *mockKeyringService) {
				tokenCmdTestSeedStore(t, k, "", []tokenCmdTestOrg{
					{id: "org-one", name: "Org One"},
				})
			},
			expectedCode: 0,
			expectedOuts: []string{"Default organization: Org One (org-one)"},
		},
		{
			name: "multiple tokens no default",
			setup: func(t *testing.T, k *mockKeyringService) {
				tokenCmdTestSeedStore(t, k, "", []tokenCmdTestOrg{
					{id: "org-one", name: "Org One"},
					{id: "org-two", name: "Org Two"},
				})
			},
			expectedCode: 0,
			expectedOuts: []string{
				"No default organization set.",
				"threatcl cloud token default <org-id>",
			},
			unexpectedOut: "Default organization:",
		},
		{
			name: "default points at missing token",
			setup: func(t *testing.T, k *mockKeyringService) {
				tokenCmdTestSeedStore(t, k, "org-gone", []tokenCmdTestOrg{
					{id: "org-one", name: "Org One"},
					{id: "org-two", name: "Org Two"},
				})
			},
			expectedCode: 0,
			expectedOuts: []string{"Default organization: org-gone (token not found)"},
		},
		{
			name:         "old token format returns error",
			setup:        func(t *testing.T, k *mockKeyringService) { tokenCmdTestSeedOldFormat(t, k) },
			expectedCode: 1,
			expectedOuts: []string{"Error retrieving tokens", "token format has changed"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyringSvc := newMockKeyringService()
			fsSvc := newMockFileSystemService()
			tt.setup(t, keyringSvc)

			cmd := tokenDefaultTestCommand(t, keyringSvc, fsSvc)

			var code int
			out := capturer.CaptureOutput(func() {
				code = cmd.Run([]string{})
			})

			if code != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d", tt.expectedCode, code)
			}

			for _, want := range tt.expectedOuts {
				if !strings.Contains(out, want) {
					t.Errorf("expected output to contain %q, got %q", want, out)
				}
			}

			if tt.unexpectedOut != "" && strings.Contains(out, tt.unexpectedOut) {
				t.Errorf("expected output to not contain %q, got %q", tt.unexpectedOut, out)
			}
		})
	}
}

func TestCloudTokenDefaultSet(t *testing.T) {
	tests := []struct {
		name            string
		setup           func(t *testing.T, k *mockKeyringService)
		args            []string
		expectedCode    int
		expectedOuts    []string
		expectedDefault string
	}{
		{
			name: "set default to other org",
			setup: func(t *testing.T, k *mockKeyringService) {
				tokenCmdTestSeedStore(t, k, "org-one", []tokenCmdTestOrg{
					{id: "org-one", name: "Org One"},
					{id: "org-two", name: "Org Two"},
				})
			},
			args:            []string{"org-two"},
			expectedCode:    0,
			expectedOuts:    []string{"Default organization set to: Org Two (org-two)"},
			expectedDefault: "org-two",
		},
		{
			name: "set default without org name",
			setup: func(t *testing.T, k *mockKeyringService) {
				tokenCmdTestSeedStore(t, k, "org-one", []tokenCmdTestOrg{
					{id: "org-one", name: "Org One"},
					{id: "org-two", name: ""},
				})
			},
			args:            []string{"org-two"},
			expectedCode:    0,
			expectedOuts:    []string{"Default organization set to: org-two\n"},
			expectedDefault: "org-two",
		},
		{
			name: "set default to unknown org",
			setup: func(t *testing.T, k *mockKeyringService) {
				k.setMockToken("tok-1", "org-one", "Org One")
			},
			args:         []string{"missing-org"},
			expectedCode: 1,
			expectedOuts: []string{
				"no token found for organization missing-org",
				"threatcl cloud token list",
			},
			expectedDefault: "org-one",
		},
		{
			name:         "set default with no tokens stored",
			setup:        func(t *testing.T, k *mockKeyringService) {},
			args:         []string{"org-one"},
			expectedCode: 1,
			expectedOuts: []string{"no token found for organization org-one"},
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

			cmd := tokenDefaultTestCommand(t, keyringSvc, fsSvc)

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

			if tt.expectedDefault != "" {
				_, defaultOrg, err := listTokens(keyringSvc, fsSvc)
				if err != nil {
					t.Fatalf("unexpected error listing tokens: %v", err)
				}
				if defaultOrg != tt.expectedDefault {
					t.Errorf("expected default org %q, got %q", tt.expectedDefault, defaultOrg)
				}
			}
		})
	}
}

func TestCloudTokenDefaultHelpAndSynopsis(t *testing.T) {
	cmd := &CloudTokenDefaultCommand{}

	if !strings.Contains(cmd.Help(), "threatcl cloud token default [org-id]") {
		t.Errorf("expected help to contain usage line, got %q", cmd.Help())
	}
	if cmd.Synopsis() == "" {
		t.Error("expected non-empty synopsis")
	}
}
