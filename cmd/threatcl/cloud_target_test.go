package main

import (
	"testing"
)

func TestDeriveAPIBaseURLFromTarget(t *testing.T) {
	tests := []struct {
		name        string
		target      string
		expected    string
		expectError bool
	}{
		{
			name:     "subdomain gets -api suffix",
			target:   "beta.threatcl.com",
			expected: "https://beta-api.threatcl.com",
		},
		{
			name:     "apex domain gets api prefix",
			target:   "threatcl.com",
			expected: "https://api.threatcl.com",
		},
		{
			name:     "already an -api host is unchanged",
			target:   "beta-api.threatcl.com",
			expected: "https://beta-api.threatcl.com",
		},
		{
			name:     "already an api subdomain is unchanged",
			target:   "api.threatcl.com",
			expected: "https://api.threatcl.com",
		},
		{
			name:     "https scheme is preserved",
			target:   "https://beta.threatcl.com",
			expected: "https://beta-api.threatcl.com",
		},
		{
			name:     "http scheme is preserved",
			target:   "http://beta.threatcl.com",
			expected: "http://beta-api.threatcl.com",
		},
		{
			name:     "port is preserved",
			target:   "beta.threatcl.com:8443",
			expected: "https://beta-api.threatcl.com:8443",
		},
		{
			name:     "deeper subdomains only map the first label",
			target:   "staging.eu.threatcl.com",
			expected: "https://staging-api.eu.threatcl.com",
		},
		{
			name:     "localhost is unchanged",
			target:   "localhost",
			expected: "https://localhost",
		},
		{
			name:     "localhost with scheme and port is unchanged",
			target:   "http://localhost:8080",
			expected: "http://localhost:8080",
		},
		{
			name:     "IP address is unchanged",
			target:   "http://127.0.0.1:8080",
			expected: "http://127.0.0.1:8080",
		},
		{
			name:     "trailing path is dropped",
			target:   "https://beta.threatcl.com/dashboard",
			expected: "https://beta-api.threatcl.com",
		},
		{
			name:        "empty target errors",
			target:      "",
			expectError: true,
		},
		{
			name:        "whitespace target errors",
			target:      "   ",
			expectError: true,
		},
		{
			name:        "unsupported scheme errors",
			target:      "ftp://beta.threatcl.com",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := deriveAPIBaseURLFromTarget(tt.target)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none (result %q)", result)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestResolveLoginAPIBaseURL(t *testing.T) {
	tests := []struct {
		name        string
		flagAPIURL  string
		flagTarget  string
		envAPIURL   string
		expected    string
		expectError bool
	}{
		{
			name:        "both flags set errors",
			flagAPIURL:  "https://beta-api.threatcl.com",
			flagTarget:  "beta.threatcl.com",
			expectError: true,
		},
		{
			name:       "api-url flag used verbatim",
			flagAPIURL: "https://custom-api.example.com",
			expected:   "https://custom-api.example.com",
		},
		{
			name:       "api-url flag trailing slash trimmed",
			flagAPIURL: "https://custom-api.example.com/",
			expected:   "https://custom-api.example.com",
		},
		{
			name:       "api-url flag without scheme gets https",
			flagAPIURL: "custom-api.example.com",
			expected:   "https://custom-api.example.com",
		},
		{
			name:       "target flag is mapped",
			flagTarget: "beta.threatcl.com",
			expected:   "https://beta-api.threatcl.com",
		},
		{
			name:       "api-url flag beats env",
			flagAPIURL: "https://flag-api.example.com",
			envAPIURL:  "https://env-api.example.com",
			expected:   "https://flag-api.example.com",
		},
		{
			name:       "target flag beats env",
			flagTarget: "beta.threatcl.com",
			envAPIURL:  "https://env-api.example.com",
			expected:   "https://beta-api.threatcl.com",
		},
		{
			name:      "env used when no flags",
			envAPIURL: "https://env-api.example.com",
			expected:  "https://env-api.example.com",
		},
		{
			name:     "default used when nothing set",
			expected: defaultAPIBaseURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsSvc := newMockFileSystemService()
			if tt.envAPIURL != "" {
				fsSvc.setEnv("THREATCL_API_URL", tt.envAPIURL)
			}

			result, err := resolveLoginAPIBaseURL(tt.flagAPIURL, tt.flagTarget, fsSvc)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none (result %q)", result)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestResolveAPIBaseURL(t *testing.T) {
	tests := []struct {
		name      string
		storedURL string
		envAPIURL string
		expected  string
	}{
		{
			name:      "env beats stored URL",
			storedURL: "https://stored-api.example.com",
			envAPIURL: "https://env-api.example.com",
			expected:  "https://env-api.example.com",
		},
		{
			name:      "stored URL used when env unset",
			storedURL: "https://stored-api.example.com",
			expected:  "https://stored-api.example.com",
		},
		{
			name:      "stored URL trailing slash trimmed",
			storedURL: "https://stored-api.example.com/",
			expected:  "https://stored-api.example.com",
		},
		{
			name:     "default when nothing set",
			expected: defaultAPIBaseURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsSvc := newMockFileSystemService()
			if tt.envAPIURL != "" {
				fsSvc.setEnv("THREATCL_API_URL", tt.envAPIURL)
			}

			result := resolveAPIBaseURL(tt.storedURL, fsSvc)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}
