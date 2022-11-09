 spec_version = "0.1.4"

 threatmodel "Modelly model" {
   imports = ["control-library/othercontrols.hcl"]
   author = "@xntrik"

   threat {
     description = "threaty threat"
     control = import.control.control_name.description
     stride = ["Spoofing", "Elevation of privilege"]
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
