spec_version = "0.3.1"

threatmodel "Sample" {
  author      = "you"
  description = "A scratch file for trying out the threatcl language server."

  information_asset "creds" {
    information_classification = "Confidential"
  }

  threat "phishing" {
    description            = "An attacker phishes a user"
    stride                 = ["Spoofing"]
    information_asset_refs = ["creds"]

    risk {
      likelihood = "high"
      impact     = "medium"
    }
  }
}
