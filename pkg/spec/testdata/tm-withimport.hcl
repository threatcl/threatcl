 spec_version = "0.0.3"

 threatmodel "test" {
   imports = ["subfolder/othercontrols.hcl", "controls.hcl"]
   author = "@xntrik"

   threat {
     description = "words"

     control = import.control.another_control_name.description
    }
 }

 threatmodel "tm1 one" {
   imports = ["controls.hcl"]
   description = <<EOT
This is some arbitrary text

But the description is wrapped over multiple lines
But the description is wrapped over multiple lines
But the description is wrapped over multiple lines
But the description is wrapped over multiple lines
But the description is wrapped over multiple lines
But the description is wrapped over multiple lines
But the description is wrapped over multiple lines
But the description is wrapped over multiple lines
EOT
   link = "https://"
   diagram_link = "https://somelink"
   author = "@xntrik"

   threat {
     description = <<EOT
This is a multi line set of input

ANd it should have spaces and all sorts of stuff in it.
EOT
     impacts = ["Confidentiality", "Availability"]
     control = import.control.control_name.description
  }

   threat {
     description = <<EOT
This is a multi line set of input
EOT
     impacts = ["integrity"]
     stride = ["spoofing", "tampering"]
  }

  usecase {
    description = "Users access the system and do something"
  }

  usecase {
    description = "Admins can see stuff too"
  }

 }
