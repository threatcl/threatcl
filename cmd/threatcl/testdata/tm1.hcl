 spec_version = "0.1.15"

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
     value = "dmz"
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

 }
