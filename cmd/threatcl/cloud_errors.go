package main

// Error message constants used across cloud commands
const (
	ErrAuthFailed          = "authentication failed - token may be invalid or expired. Please run 'threatcl cloud login' again"
	ErrRetrievingToken     = "error retrieving token"
	ErrPleaseLogin         = "please run 'threatcl cloud login' to authenticate."
	ErrNoOrganizations     = "error: No organizations found. Please specify an organization ID with -org-id"
	ErrFailedToConnect     = "failed to connect to API"
	ErrFailedToCreateReq   = "failed to create request"
	ErrFailedToParseResp   = "failed to parse response"
	ErrFailedToReadFile    = "failed to read file"
	ErrFailedToWriteFile   = "failed to write file"
	ErrFileAlreadyExists   = "file %s already exists. Use -overwrite flag to overwrite"
	ErrThreatModelNotFound = "threat model not found: %s"
	ErrAPIReturnedStatus   = "api returned status %d: %s"

	// Library-related errors
	ErrLibraryFolderNotFound    = "library folder not found: %s"
	ErrLibraryThreatNotFound    = "threat library item not found: %s"
	ErrLibraryControlNotFound   = "control library item not found: %s"
	ErrInvalidLibraryFolderType = "invalid folder type: %s (must be THREAT or CONTROL)"
	ErrInvalidLibraryStatus     = "invalid status: %s (must be DRAFT, PUBLISHED, ARCHIVED, or DEPRECATED)"
)
