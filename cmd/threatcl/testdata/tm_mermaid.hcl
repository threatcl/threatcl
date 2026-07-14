spec_version = "0.6.0"

threatmodel "mermaid model" {
  description = "A model that embeds a free-form mermaid diagram"
  author      = "@cfrichot"

  mermaid "Login sequence" {
    description = "How a user authenticates"
    content     = <<-EOT
      sequenceDiagram
        User->>App: credentials
        App->>Auth: verify
        Auth-->>App: token
    EOT
  }

  threat "intercept" {
    description = "Credentials are intercepted"
    stride      = ["Spoofing"]
  }
}
