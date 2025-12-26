 spec_version = "0.2.3"

 threatmodel "Demonstrate control_imports" {
   imports = ["control-library/expanded-controls.hcl"]
   author = "@xntrik"

   threat "threaty threat" {
     description = "threaty threat"
     stride = ["Spoofing", "Elevation of privilege"]

     control_imports = ["import.control.authentication_control"]

   }

 }
