 spec_version = "0.2.3"

 threatmodel "tm2 one" {
   description = "This is some arbitrary text"
   link = "https://"
   author = "@cfrichot"

   threat "threaty threat" {
     description = "threaty threat"
     control = "controlly control"
   }

 }
 threatmodel "tm2 two" {
   description = "This is some arbitrary text"
   link = "https://"
   author = "@cfrichot"
   diagram_link = "https://bleep.com"

   attributes {
     new_initiative = "true"
     initiative_size = "medium"
     internet_facing = false
   }

   information_asset "cred store" {
     description = "This is where creds are stored"
     information_classification = "Restricted"
   }

   information_asset "audit store" {
     description = "This is where creds are stored"
     information_classification = "Restricted"
   }

 }
