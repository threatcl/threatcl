 spec_version = "0.2.0"

 threatmodel "Modelly model" {
   imports = ["https://raw.githubusercontent.com/xntrik/hcltm/main/examples/aws-security-checklist.hcl", "https://raw.githubusercontent.com/xntrik/hcltm/main/examples/owasp-proactive-controls.hcl"]
   author = "@xntrik"

   diagram_link = "https://link.to.somewhere/diagram"

   threat {
     description = "threaty threat"
#      control = <<EOT
# * ${import.control.aws-iam-awsorgs.description}
# * ${import.control.aws-iam-root.description}
# EOT
     stride = ["Spoofing", "Elevation of privilege"]

     expanded_control "AWS Orgs" {
       description = import.control.aws-iam-awsorgs.description
       implemented = true
       risk_reduction = 40
     }

     expanded_control "Root Account Lockdown" {
       description = import.control.aws-iam-root.description
       implemented = true
       risk_reduction = 50
     }
   }

   threat {
     description = "Something else" 
     # control = import.control.owasp-errors-infoleak.description

     # proposed_control {
     #   implemented = false
     #   description = "Do the thing"
     # }
     expanded_control "Prevent Leakage" {
       description = import.control.owasp-errors-infoleak.description
       risk_reduction = 10
     }

     expanded_control "Do the thing" {
       description = "Yep do it"
       risk_reduction = 30
     }

     # proposed_control {
     #   implemented = true
     #   description = "Do another thing"
     # }

     expanded_control "Do another thing" {
       description = "Also do this other thing"
       risk_reduction = 30
     }

     expanded_control "thing" {
       description = "This is the new type of control"
       risk_reduction = 40
     }
   }

   threat {
     description = "Something else that is also equally as bad"

     expanded_control "trusted libraries" {
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
