spec_version = "0.3.0"

threatmodel "Test Model" {
  author      = "xntrik"
  description = "a test model"

  information_asset "creds" {
    information_classification = "Confidential"
  }

  threat "phishing" {
    description            = "An attacker phishes a user"
    stride                 = ["Spoofing", "Tampering"]
    impacts                = ["Confidentiality"]
    information_asset_refs = ["creds"]

    risk {
      likelihood = "high"
      impact     = "medium"
    }

    control "mfa" {
      description = "use MFA"
      implemented = true
    }
  }
}
