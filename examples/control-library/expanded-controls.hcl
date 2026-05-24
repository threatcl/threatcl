spec_version = "0.2.6"
component "control" "authentication_control" {
  description = "Multi-factor authentication required"
  implemented = true
  implementation_notes = "Using TOTP for all admin accounts"
  risk_reduction = 80
  
  attribute "category" {
    value = "Authentication"
  }
  
  attribute "framework" {
    value = "NIST"
  }
}
