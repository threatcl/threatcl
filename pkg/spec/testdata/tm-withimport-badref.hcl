 spec_version = "0.0.3"

 threatmodel "test" {
   imports = ["subfolder/othercontrols.hcl"]
   author = "@xntrik"

   threat {
     description = "words"

     control = import.control.aer_control_name.description
    }
 }
