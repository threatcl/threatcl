 spec_version = "0.1.3"

 threatmodel "tm2 one" {
   description = "This is some arbitrary text"
   link = "https://"
   author = "@cfrichot"

   threat {
     description = "threaty threat"
     control = "controlly control"
     stride = ["Spoofing", "Elevation of privilege"]
     information_asset_refs = []
   }

   data_flow_diagram {
     external_element "Google Analytics" {}

     process "Client" {
       trust_zone = "Browser"
     }

     flow "https" {
       from = "Client"
       to = "Google Analytics"
     }

     process "Web Server" {
       trust_zone = "AWS"
     }

     data_store "Logs" {
       trust_zone = "AWS"
     }

     flow "TCP" {
       from = "Web Server"
       to = "Logs"
     }

     data_store "sqlite" {
       trust_zone = "AWS"
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
