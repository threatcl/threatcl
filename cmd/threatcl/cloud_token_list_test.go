package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zenizh/go-capturer"
)

// tokenCmdTestOrg describes an organization token to seed into the mock
// keyring token store. Shared by the token list/remove/default and logout
// command tests.
type tokenCmdTestOrg struct {
	id        string
	name      string
	token     string
	expiresAt *int64
	apiURL    string
}

// tokenCmdTestSeedStore writes a v2 token store with the given orgs and
// default org into the mock keyring.
func tokenCmdTestSeedStore(t testing.TB, k *mockKeyringService, defaultOrg string, orgs []tokenCmdTestOrg) {
	t.Helper()

	store := tokenStore{
		Version:    tokenStoreVersion,
		DefaultOrg: defaultOrg,
		Tokens:     make(map[string]orgTokenData),
	}
	for _, o := range orgs {
		tok := o.token
		if tok == "" {
			tok = "token-" + o.id
		}
		store.Tokens[o.id] = orgTokenData{
			AccessToken: tok,
			TokenType:   "Bearer",
			ExpiresAt:   o.expiresAt,
			OrgName:     o.name,
			ApiURL:      o.apiURL,
		}
	}

	data, err := json.Marshal(store)
	if err != nil {
		t.Fatalf("failed to marshal token store: %v", err)
	}
	if err := k.SetRaw(tokenStoreKeyringKey, data); err != nil {
		t.Fatalf("failed to seed token store: %v", err)
	}
}

// tokenCmdTestSeedOldFormat seeds an old (v1) single-token format into the
// mock keyring, which the token store helpers reject with a migration error.
func tokenCmdTestSeedOldFormat(t testing.TB, k *mockKeyringService) {
	t.Helper()

	err := k.Set("access_token", map[string]interface{}{
		"access_token": "old-format-token",
	})
	if err != nil {
		t.Fatalf("failed to seed old format token: %v", err)
	}
}

// tokenCmdTestInt64Ptr returns a pointer to v.
func tokenCmdTestInt64Ptr(v int64) *int64 {
	return &v
}

func tokenListTestCommand(t testing.TB, k *mockKeyringService, f *mockFileSystemService) *CloudTokenListCommand {
	t.Helper()

	return &CloudTokenListCommand{
		CloudCommandBase: CloudCommandBase{
			GlobalCmdOptions: &GlobalCmdOptions{},
			httpClient:       newMockHTTPClient(),
			keyringSvc:       k,
			fsSvc:            f,
		},
	}
}

func TestCloudTokenListRun(t *testing.T) {
	pastExpiry := tokenCmdTestInt64Ptr(time.Now().Add(-1 * time.Hour).Unix())
	futureExpiry := tokenCmdTestInt64Ptr(time.Now().Add(24 * time.Hour).Unix())

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
			name: "single token with default",
			setup: func(t *testing.T, k *mockKeyringService) {
				k.setMockToken("tok-1", "org-one", "Test Org")
			},
			expectedCode: 0,
			expectedOuts: []string{
				"ORG ID",
				"ORG NAME",
				"org-one",
				"Test Org",
				"Valid",
				"Default organization: org-one",
			},
		},
		{
			name: "multiple tokens with default",
			setup: func(t *testing.T, k *mockKeyringService) {
				tokenCmdTestSeedStore(t, k, "org-two", []tokenCmdTestOrg{
					{id: "org-one", name: "Org One"},
					{id: "org-two", name: "Org Two"},
				})
			},
			expectedCode: 0,
			expectedOuts: []string{
				"org-one",
				"Org One",
				"org-two",
				"Org Two",
				"Default organization: org-two",
			},
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
				"threatcl cloud token default",
			},
			unexpectedOut: "Default organization:",
		},
		{
			name: "expired token shows expired status",
			setup: func(t *testing.T, k *mockKeyringService) {
				tokenCmdTestSeedStore(t, k, "org-one", []tokenCmdTestOrg{
					{id: "org-one", name: "Org One", expiresAt: pastExpiry},
				})
			},
			expectedCode: 0,
			expectedOuts: []string{"Expired"},
		},
		{
			name: "unexpired token shows valid status",
			setup: func(t *testing.T, k *mockKeyringService) {
				tokenCmdTestSeedStore(t, k, "org-one", []tokenCmdTestOrg{
					{id: "org-one", name: "Org One", expiresAt: futureExpiry},
				})
			},
			expectedCode: 0,
			expectedOuts: []string{"Valid"},
		},
		{
			name: "missing org name shows unknown",
			setup: func(t *testing.T, k *mockKeyringService) {
				tokenCmdTestSeedStore(t, k, "org-one", []tokenCmdTestOrg{
					{id: "org-one", name: ""},
				})
			},
			expectedCode: 0,
			expectedOuts: []string{"(unknown)"},
		},
		{
			name: "long org name is truncated",
			setup: func(t *testing.T, k *mockKeyringService) {
				tokenCmdTestSeedStore(t, k, "org-one", []tokenCmdTestOrg{
					{id: "org-one", name: "An Extremely Long Organization Name"},
				})
			},
			expectedCode: 0,
			expectedOuts: []string{"An Extremely Long..."},
		},
		{
			name: "stored endpoint is displayed",
			setup: func(t *testing.T, k *mockKeyringService) {
				tokenCmdTestSeedStore(t, k, "org-one", []tokenCmdTestOrg{
					{id: "org-one", name: "Org One", apiURL: "https://b-api.threatcl.com"},
					{id: "org-two", name: "Org Two"},
				})
			},
			expectedCode: 0,
			expectedOuts: []string{
				"ENDPOINT",
				"https://b-api.threatcl.com",
				"(default)",
			},
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

			cmd := tokenListTestCommand(t, keyringSvc, fsSvc)

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

func TestCloudTokenListDefaultMarker(t *testing.T) {
	keyringSvc := newMockKeyringService()
	fsSvc := newMockFileSystemService()

	tokenCmdTestSeedStore(t, keyringSvc, "org-two", []tokenCmdTestOrg{
		{id: "org-one", name: "Org One"},
		{id: "org-two", name: "Org Two"},
	})

	cmd := tokenListTestCommand(t, keyringSvc, fsSvc)

	var code int
	out := capturer.CaptureOutput(func() {
		code = cmd.Run([]string{})
	})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	var sawDefault, sawNonDefault bool
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "org-two ") {
			sawDefault = true
			if !strings.HasSuffix(trimmed, "*") {
				t.Errorf("expected default org line to end with %q, got %q", "*", trimmed)
			}
		}
		if strings.HasPrefix(trimmed, "org-one ") {
			sawNonDefault = true
			if strings.HasSuffix(trimmed, "*") {
				t.Errorf("expected non-default org line to not end with %q, got %q", "*", trimmed)
			}
		}
	}

	if !sawDefault {
		t.Errorf("expected output to contain a line for org-two, got %q", out)
	}
	if !sawNonDefault {
		t.Errorf("expected output to contain a line for org-one, got %q", out)
	}
}

func TestCloudTokenListHelpAndSynopsis(t *testing.T) {
	cmd := &CloudTokenListCommand{}

	if !strings.Contains(cmd.Help(), "threatcl cloud token list") {
		t.Errorf("expected help to contain usage line, got %q", cmd.Help())
	}
	if cmd.Synopsis() == "" {
		t.Error("expected non-empty synopsis")
	}
}
