 spec_version = "0.0.5"

 threatmodel "Modelly model" {
   imports = ["aws-security-checklist.hcl", "owasp-proactive-controls.hcl"]
   author = "@xntrik"

   threat {
     description = "threaty threat"
     control = <<EOT
* ${import.control.aws-iam-awsorgs.description}
* ${import.control.aws-iam-root.description}
EOT
     stride = ["Spoofing", "Elevation of privilege"]
   }

   threat {
     description = "Something else" 
     control = import.control.owasp-errors-infoleak.description
   }

 }
