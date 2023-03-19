 spec_version = "0.0.3"

 threatmodel "tm1 one" {
   description = <<EOT
This is some arbitrary text

But the description is wrapped over multiple lines
But the description is wrapped over multiple lines
But the description is wrapped over multiple lines
But the description is wrapped over multiple lines
But the description is wrapped over multiple lines
But the description is wrapped over multiple lines
But the description is wrapped over multiple lines
But the description is wrapped over multiple lines
EOT
   link = "https://"
   diagram_link = "https://somelink"
   author = "@xntrik"

   threat {
     description = <<EOT
This is a multi line set of input

ANd it should have spaces and all sorts of stuff in it.
EOT
     impacts = ["Confidentiality", "Availability"]
  }

   threat {
     description = <<EOT
This is a multi line set of input
EOT
     impacts = ["integrity"]
     stride = ["spoofing", "tampering"]
  }

  usecase {
    description = "Users access the system and do something"
  }

  usecase {
    description = "Admins can see stuff too"
  }

  exclusion {
    description = "An exclusion"
  }

  exclusion {
    description = "A second exclusiion"
  }

 }
 threatmodel "tm tm1 two" {
   description = "This is some arbitrary text"
   link = "https://"
   author = "@cfrichot"
   diagram_link = "https://i.imgur.com/AzxrMsp.jpg"
   created_at = 1594033151
   updated_at = 1594033160

   attributes {
     new_initiative = false
     initiative_size = "small"
     internet_facing = true
   }

   additional_attribute "network_segment" {
     value = "DMZ"
   }

   information_asset "cred store" {
     description = "This is where creds are stored"
     information_classification = "Restricted"
   }

   information_asset "audit store" {
     description = "This is where creds are stored"
     information_classification = "Top Secret"
   }

   third_party_dependency "IdP" {
     description = "This is 3rd party IdP"
     uptime_dependency = "degraded"
     saas = "true"
     paying_customer = "true"
   }

   data_flow_diagram {

    process "update data" {}

    process "update password" {
      trust_zone = "secure zone"
    }

    data_store "password db" {
      trust_zone = "secure zone"
      information_asset = "cred store"
    }

    external_element "user" {}

    flow "https" {
      from = "user"
      to = "update data"
    }

    flow "https" {
      from = "user"
      to = "update password"
    }

    flow "tcp" {
      from = "update password"
      to = "password db"
    }

    trust_zone "public zone" {

      process "visit external site" {}

      external_element "OIDC Provider" {}

    }

   }

 }
