 spec_version = "0.0.3"

 threatmodel "test" {
   imports = ["nope/othercontrols.hcl"]
   author = "@xntrik"

   threat {
     description = "words"

     control = import.control.another_control_name.description
    }
 }
