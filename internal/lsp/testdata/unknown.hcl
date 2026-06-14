threatmodel "Unknowns" {
  author     = "x"
  bogus_attr = "nope"

  bogus_block {
    foo = "bar"
  }

  threat "t" {
    description = "a threat"
  }
}
