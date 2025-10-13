spec_version = "0.1.15"

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
  }

  threat {
    description = "Something else that is risky"

    # proposed_control {
    #   implemented = false
    #   description = "Do the thing"
    # }

    expanded_control "Do the thing" {
      description = "And do it well"
      implemented = true
      risk_reduction = 10
    }

    # proposed_control {
    #   implemented = true
    #   description = "Do another thing"
    # }

    expanded_control "Do another thing" {
      description = "more words about the control"
      implemented = true
      risk_reduction = 10
    }
  }

}
