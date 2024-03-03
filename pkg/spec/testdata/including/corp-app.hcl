spec_version = "0.1.8"

threatmodel "Tower of London" {

  author = "@xntrik"

  including = "shared/tower.hcl"

  information_asset "something else" {
    description = "this is another asset - a new asset"
  }

  information_asset "crown jewels2" {
    description = "but override now - including the imperial state crown2"
    information_classification = "Confidential"
  }

  usecase {
    description = "another uc perhaps"
  }

  threat {
    description = "Someone who isn't the Queen defaces the crown"
    impacts = ["Confidentiality"]
    control = "Lots of guards"
  }

}

threatmodel "Tower of France" {

  author = "@xntrik"
  link = "har"

  threat {
    description = "Someone who isn't the Queen defaces the crown"
    impacts = ["Confidentiality"]
    control = "Lots of guards"
  }

}
