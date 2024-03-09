spec_version = "0.1.9"

threatmodel "Tower of London" {

  author = "@xntrik"
  link = "har"

  including = "./shared/tower.hcl"

  information_asset "something else" {
    description = "this is another asset - a new asset"
  }

  usecase {
    description = "another uc perhaps"
  }

  threat {
    description = "Someone who isn't the Queen defaces the crown"
    impacts = ["Confidentiality"]
  }

}

threatmodel "Tower of France" {

  author = "@xntrik"
  link = "har"

  threat {
    description = "Someone who isn't the Queen defaces the crown"
    impacts = ["Confidentiality"]
  }

}
