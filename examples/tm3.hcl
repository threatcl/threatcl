 spec_version = "0.2.3"

 threatmodel "Modelly model" {
   imports = ["https://raw.githubusercontent.com/xntrik/hcltm/main/examples/aws-security-checklist.hcl", "https://raw.githubusercontent.com/xntrik/hcltm/main/examples/owasp-proactive-controls.hcl"]
   author = "@xntrik"

   diagram_link = "https://link.to.somewhere/diagram"

   threat "threaty threat" {
     description = "threaty threat"
#      control = <<EOT
# * ${import.control.aws-iam-awsorgs.description}
# * ${import.control.aws-iam-root.description}
# EOT
     stride = ["Spoofing", "Elevation of privilege"]

     control "AWS Orgs" {
       description = import.control.aws-iam-awsorgs.description
       implemented = true
       risk_reduction = 40
     }

     control "Root Account Lockdown" {
       description = import.control.aws-iam-root.description
       implemented = true
       risk_reduction = 50
     }
   }

   threat "Something else" {
     description = "Something else" 
     # control = import.control.owasp-errors-infoleak.description

     # proposed_control {
     #   implemented = false
     #   description = "Do the thing"
     # }
     control "Prevent Leakage" {
       description = import.control.owasp-errors-infoleak.description
       risk_reduction = 10
     }

     control "Do the thing" {
       description = "Yep do it"
       risk_reduction = 30
     }

     # proposed_control {
     #   implemented = true
     #   description = "Do another thing"
     # }

     control "Do another thing" {
       description = "Also do this other thing"
       risk_reduction = 30
     }

     control "thing" {
       description = "This is the new type of control"
       risk_reduction = 40
     }
   }

   threat "Bad threat" {
     description = "Something else that is also equally as bad"

     control "trusted libraries" {
       implemented = false
       description = import.control.owasp-secframework-trustedlibs.description
       risk_reduction = 50

       attribute "proactive_control" {
         value = "C2"
       }

       attribute "url" {
         value = "https://owasp.org/www-project-proactive-controls/v3/en/c2-leverage-security-frameworks-libraries"
       }
     }
   }

 }
