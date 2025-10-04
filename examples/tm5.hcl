 spec_version = "0.1.14"

 threatmodel "Demonstrate control_imports" {
   imports = ["control-library/expanded-controls.hcl"]
   author = "@xntrik"

   threat {
     description = "threaty threat"
     stride = ["Spoofing", "Elevation of privilege"]

     control_imports = ["import.expanded_control.authentication_control"]

   }

 }
