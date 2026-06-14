threatmodel "Bad Enums" {
  author = "x"

  threat "t" {
    description = "a threat"
    stride      = ["Spoofing", "Nonsense"]

    risk {
      likelihood = "extremely_high"
      impact     = "medium"
    }
  }
}
