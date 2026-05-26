package main

// JSON type definitions for API responses

type deviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	UserCode        string `json:"user_code"`
	VerificationURL string `json:"verification_url"`
}

type tokenResponse struct {
	AccessToken    string `json:"access_token"`
	TokenType      string `json:"token_type"`
	OrganizationID string `json:"organization_id"`
	ExpiresAt      *int64 `json:"expires_at,omitempty"`
}

// Token store types for multi-org token management

// tokenStore holds all tokens and configuration for multi-org support
type tokenStore struct {
	Version    int                     `json:"version"`
	DefaultOrg string                  `json:"default_org,omitempty"`
	Tokens     map[string]orgTokenData `json:"tokens"`
}

// orgTokenData holds token data for a specific organization
type orgTokenData struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresAt   *int64 `json:"expires_at,omitempty"`
	OrgName     string `json:"org_name,omitempty"`
}

type errorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Status  int    `json:"status"`
	} `json:"error"`
}

type whoamiResponse struct {
	ID                       string          `json:"id"`
	User                     userInfo        `json:"user"`
	Organizations            []orgMembership `json:"organizations"`
	ApiTokenOrganizationID   string          `json:"api_token_organization_id,omitempty"`
	ApiTokenOrganizationName string          `json:"api_token_organization_name,omitempty"`
}

type userInfo struct {
	ID                  string                 `json:"id"`
	Email               string                 `json:"email"`
	EmailVerified       bool                   `json:"email_verified"`
	FullName            string                 `json:"full_name"`
	AvatarURL           string                 `json:"avatar_url"`
	FailedLoginAttempts int                    `json:"failed_login_attempts"`
	Settings            map[string]interface{} `json:"settings"`
	CreatedAt           string                 `json:"created_at"`
	UpdatedAt           string                 `json:"updated_at"`
}

type orgMembership struct {
	Organization orgInfo `json:"organization"`
	Role         string  `json:"role"`
	JoinedAt     string  `json:"joined_at"`
}

type orgInfo struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Slug             string                 `json:"slug"`
	SubscriptionTier string                 `json:"subscription_tier"`
	MaxUsers         int                    `json:"max_users"`
	MaxThreatModels  int                    `json:"max_threat_models"`
	MaxStorageKB     int                    `json:"max_storage_kb"`
	CurUsers         int                    `json:"cur_users"`
	CurThreatModels  int                    `json:"cur_threat_models"`
	CurStorageKB     int                    `json:"cur_storage_kb"`
	Settings         map[string]interface{} `json:"settings"`
	CreatedAt        string                 `json:"created_at"`
	UpdatedAt        string                 `json:"updated_at"`
}

type threatModel struct {
	ID                        string   `json:"id"`
	OrganizationID            string   `json:"organization_id"`
	Name                      string   `json:"name"`
	Slug                      string   `json:"slug"`
	Description               string   `json:"description"`
	Status                    string   `json:"status"`
	Version                   string   `json:"version"`
	SpecFilePath              string   `json:"spec_file_path"`
	AssetCount                int      `json:"asset_count"`
	ThreatCount               int      `json:"threat_count"`
	ControlCount              int      `json:"control_count"`
	DataFlowCount             int      `json:"data_flow_count"`
	UseCaseCount              int      `json:"use_case_count"`
	ExclusionCount            int      `json:"exclusion_count"`
	ThirdPartyDependencyCount int      `json:"tpd_count"`
	Tags                      []string `json:"tags"`
	CreatedBy                 string   `json:"created_by"`
	CreatedAt                 string   `json:"created_at"`
	UpdatedAt                 string   `json:"updated_at"`
	URL                       string   `json:"url,omitempty"`
}

type threatModelVersion struct {
	ID                        string `json:"id"`
	IsCurrent                 bool   `json:"is_current"`
	ThreatModelID             string `json:"threat_model_id"`
	Version                   string `json:"version"`
	SpecFilePath              string `json:"spec_file_path"`
	SpecFileSizeBytes         int    `json:"spec_file_size_bytes"`
	SpecFileHash              string `json:"spec_file_hash"`
	AssetCount                int    `json:"asset_count"`
	ThreatCount               int    `json:"threat_count"`
	ControlCount              int    `json:"control_count"`
	DataFlowCount             int    `json:"data_flow_count"`
	UseCaseCount              int    `json:"use_case_count"`
	ExclusionCount            int    `json:"exclusion_count"`
	ThirdPartyDependencyCount int    `json:"tpd_count"`
	CreatedAt                 string `json:"created_at"`
	ChangedBy                 string `json:"changed_by"`
}

type threatModelVersionsResponse struct {
	Versions []threatModelVersion `json:"versions"`
	Total    int                  `json:"total"`
}
