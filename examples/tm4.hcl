spec_version = "0.2.3"

threatmodel "Sumpidy" {
  author = "@xntrik"

  including = "tm3.hcl"

  data_flow_diagram_v2 "DFD" {
    process "test" {}
  }
}
