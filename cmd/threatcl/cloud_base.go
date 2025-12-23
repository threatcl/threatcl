package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"
)

// CloudCommandBase provides common functionality for all cloud commands
type CloudCommandBase struct {
	*GlobalCmdOptions
	httpClient HTTPClient
	keyringSvc KeyringService
	fsSvc      FileSystemService
}

// initDependencies initializes all dependencies with defaults if not set
// Returns the initialized httpClient, keyringSvc, and fsSvc
func (b *CloudCommandBase) initDependencies(timeout time.Duration) (HTTPClient, KeyringService, FileSystemService) {
	httpClient := b.httpClient
	if httpClient == nil {
		httpClient = &defaultHTTPClient{
			client: &http.Client{
				Timeout: timeout,
			},
		}
	}

	keyringSvc := b.keyringSvc
	if keyringSvc == nil {
		keyringSvc = &defaultKeyringService{}
	}

	fsSvc := b.fsSvc
	if fsSvc == nil {
		fsSvc = &defaultFileSystemService{}
	}

	return httpClient, keyringSvc, fsSvc
}

// getTokenWithDeps retrieves the authentication token using provided dependencies
func (b *CloudCommandBase) getTokenWithDeps(keyringSvc KeyringService, fsSvc FileSystemService) (string, error) {
	token, err := getToken(keyringSvc, fsSvc)
	if err != nil {
		return "", fmt.Errorf("%s: %w", ErrRetrievingToken, err)
	}
	return token, nil
}

// handleTokenError prints token-related errors to stderr and returns exit code
func (b *CloudCommandBase) handleTokenError(err error) int {
	fmt.Fprintf(os.Stderr, "%s\n", err)
	fmt.Fprintf(os.Stderr, "%s\n", ErrPleaseLogin)
	return 1
}

// resolveOrgId resolves organization ID from flag or user profile
// If flagOrgId is empty, fetches user info and uses the first organization
func (b *CloudCommandBase) resolveOrgId(token string, flagOrgId string, httpClient HTTPClient, fsSvc FileSystemService) (string, error) {
	if flagOrgId != "" {
		return flagOrgId, nil
	}

	// Fetch user info to get first organization
	whoamiResp, err := fetchUserInfo(token, httpClient, fsSvc)
	if err != nil {
		return "", fmt.Errorf("error fetching user information: %w", err)
	}

	if len(whoamiResp.Organizations) == 0 {
		return "", errors.New(ErrNoOrganizations)
	}

	return whoamiResp.Organizations[0].Organization.ID, nil
}
