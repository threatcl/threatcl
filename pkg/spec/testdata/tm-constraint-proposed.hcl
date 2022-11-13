 spec_version = "0.0.3"

 threatmodel "tm1 one" {
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
   author = "@xntrik"

   threat {
     description = <<EOT
This is a multi line set of input

ANd it should have spaces and all sorts of stuff in it.
EOT
     impacts = ["Confidentiality", "Availability"]

     proposed_control {
       implemented = false
       description = "blep"
     }
  }
}

