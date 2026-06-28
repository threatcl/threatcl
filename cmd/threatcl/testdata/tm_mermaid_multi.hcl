spec_version = "0.4.0"

threatmodel "mermaid multi" {
  description = "A model that embeds multiple free-form mermaid diagrams"
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

  mermaid "State machine" {
    description = "Session lifecycle"
    content     = <<-EOT
      stateDiagram-v2
        [*] --> Anonymous
        Anonymous --> Authenticated: login
        Authenticated --> Anonymous: logout
    EOT
  }
}
