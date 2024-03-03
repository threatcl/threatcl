 spec_version = "0.1.8"

 threatmodel "tm1 one" {
   description = <<EOT
This is some arbitrary text

EOT
   author = "@xntrik"

   threat {
     description = <<EOT
This is a multi line set of input

ANd it should have spaces and all sorts of stuff in it.
EOT
     impacts = ["Confidentiality", "Availability"]
  }

 data_flow_diagram {
   external_element "Google Analytics" {}

   trust_zone "Browser" {

     process "Client" {}
   }

   trust_zone "AWS" {
     process "Web Server" {}

     data_store "Logs" {}

     data_store "sqlite" {}


   }

   flow "https" {
     from = "Client"
     to = "Google Analytics"
   }

   flow "TCP" {
     from = "Web Server"
     to = "Logs"
   }

   flow "https" {
     from = "Client"
     to = "Web Server"
    }

    flow "https" {
      from = "Web Server"
      to = "sqlite"
    }

    flow "https" {
      from = "sqlite"
      to = "Web Server"
    }
 
 }


}

