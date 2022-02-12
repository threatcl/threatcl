spec_version = "0.1.1"

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

  third_party_dependency "community watch" {
    description = "The community watch helps guard the premise"
    uptime_dependency = "degraded"
  }

  threat {
    description = "Someone who isn't the Queen steals the crown"
    impacts = ["Confidentiality"]
    control = "Lots of guards"
  }

}

threatmodel "Fort Knox" {
  description = "A .. fort?"
  author = "@xntrik"

  attributes {
    new_initiative = "false"
    internet_facing = "true"
    initiative_size = "Small"
  }

  information_asset "Gold" {
    description = "Lots of gold"
    information_classification = "Confidential"
  }

  usecase {
    description = "Only the correct people can access the gold"
  }

  threat {
    description = "Someone steals the gold"
    impacts = ["Confidentiality"]
    control = "Big walls"
  }

}
