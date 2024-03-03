spec_version = "0.1.8"

threatmodel "Tower of London" {
  description = "A historic castle"
  author = "@xntrik"

  attributes {
    new_initiative = "true"
    internet_facing = "true"
    initiative_size = "Small"
  }

  information_asset "crown jewels" {
    description = "including the imperial state crown"
    information_classification = "Confidential"
  }

  information_asset "crown jewels2" {
    description = "I should be overriden"
    information_classification = "Confidential"
  }

  usecase {
    description = "The Queen can fetch the crown"
  }

  exclusion {
    description = "This is an upstream exclusion"
  }

  third_party_dependency "community watch" {
    description = "The community watch helps guard the premise"
    uptime_dependency = "degraded"
  }

  threat {
    description = "Someone who isn't the Queen steals the crown"
    impacts = ["Confidentiality"]
    control = "Lots of guards"
  }

  threat {
    description = "Something else that is risky"

    proposed_control {
      implemented = false
      description = "Do the thing"
    }

    proposed_control {
      implemented = true
      description = "Do another thing"
    }
  }

}
