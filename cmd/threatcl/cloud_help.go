package main

// cloudEnvVarHelp returns the standard "Environment Variables" help section for
// cloud commands that accept an -org-id flag. It is appended to a command's
// usage/options text; the caller is expected to strings.TrimSpace the result.
func cloudEnvVarHelp() string {
	return `
Environment Variables:

 THREATCL_API_URL
   Override the API base URL (default: ` + defaultAPIBaseURL + `)

 THREATCL_CLOUD_ORG
   Default organization ID to use when -org-id is not specified.

 THREATCL_API_TOKEN
   Provide an API token directly, bypassing the local token store.
   Useful for CI/CD pipelines and automation.
`
}

// cloudEnvVarHelpNoOrg returns the standard "Environment Variables" help section
// for cloud commands that do not accept an -org-id flag (so THREATCL_CLOUD_ORG is
// omitted). It is appended to a command's usage/options text; the caller is
// expected to strings.TrimSpace the result.
func cloudEnvVarHelpNoOrg() string {
	return `
Environment Variables:

 THREATCL_API_URL
   Override the API base URL (default: ` + defaultAPIBaseURL + `)

 THREATCL_API_TOKEN
   Provide an API token directly, bypassing the local token store.
   Useful for CI/CD pipelines and automation.
`
}
