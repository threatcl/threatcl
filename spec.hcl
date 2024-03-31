// To cater for multiple spec versions we specify this in our HCL files
spec_version = "0.1.9"

// You can include variables outside your threatmodel blocks

variable "variable_name" {
  value = "Variable text here"
}

// To use this, simply swap in a text attribute for var.variable_name

// There may be multiple threatmodel blocks in a single file, but their names must be unique

threatmodel "threatmodel name" {
  // the author attribute is required
  author = "@xntrik"

  // the including attribute is optional
  // you can inherit all the information from another threat model
  //
  // the included file must include only a single threatmodel block
  //
  // any duplicate fields will be overwritten by this threatmodel
  //
  // You can leverage go-getter's format for downloading too, this means that
  // you can refer to remote URLs, or Git Repos etc
  // See https://github.com/hashicorp/go-getter for examples
  //
  // There are some issues to select an individual file from a Git repo, as the
  // entire repo is downloaded by default. To use an individual file, you can
  // github.com/threatcl/threatcl|examples/aws-security-checklist.hcl
  // with the | being a separator between the git repo and the file to use
  // after cloning.

  including = "shared/city-threatmodel.hcl"

  // The description is optional
  description = "A description of the system being assessed"

  // The link is optional
  link = "https://link/to/docs"

  // The diagram_link is optional
  // If it ends in .jpg or .png then it'll be embedded in the resultant dashboard

  // If a diagram_link isn't set, but the threatmodel includes a
  // data_flow_diagram, this will be automatically generated and included
  // when running threatcl dashboard

  diagram_link = "https://link/to/diagram"

  // created_at and updated_at are optional integer, UNIX time stamps
  created_at = 1594033151
  updated_at = 1594033160

  // the attributes block is optional, but recommended

  attributes {
    new_initiative = "true" // boolean
    internet_facing = "true" // boolean

    // initiative_size must be one of 'Undefined, Small, Medium, Large'
    initiative_size = "Undefined"
  }

  // you can set mutiple additional attribute key/value blocks as well

  additional_attribute "network_segment" {
    value = "DMZ"
  }

  // Each threatmodel may contain a number of information_assets
  // the names must be unique per threatmodel though

  information_asset "cred store" {
    // The description is optional
    description = "This is where creds are stored"

    // information_classification must be one of 'Restricted, Confidential, Public'
    information_classification = "Confidential"

    // source is optional, and can be used to specify if this asset was sourced
    // from an external resource, such as terraform
    source = "terraform"
  }

  information_asset "special sauce" {
    // Here is how you can refer to your variables set above
    description = var.variable_name
    information_classification = "Confidential"
  }

  // Each threatmodel may contain a number of usecases

  usecase {
    // The description is required
    // Similar to threats, the description may also use multiline entries too
    description = "Users access data from the system"
  }

  // Each threatmodel may contain a number of exclusions

  exclusion {
    // The description is required
    // Similar to threats, the description may also use multiline entries too
    description = "Crypto operations are offloaded to a KMS"
  }

  // Each threatmodel may contain a number of third party dependencies

  third_party_dependency "dependency name" {
    // The description is required, and may use multiline entries
    description = "What the dependency is used for"

    // The following boolean attributes are optional and will default to false if unset
    saas = "true"
    paying_customer = "true"
    open_source = "false"
    infrastructure = "false"

    // The uptime dependency is required, and must be one of "none", "degraded", "hard", "operational"
    // This specifies the impact to our system if the dependency is unavailable
    uptime_dependency = "none"

    // Uptime notes are optional
    uptime_notes = "If this dependency goes down users can't login"
  }

  // Each threatmodel may contain a number of threats

  threat {
    // The description is required
    description = "System is compromised by hackers"

    // The impact is an optional array of potential impact values
    // The available values are 'Confidentiality, Integrity, Availability'
    impacts = ["Confidentiality", "Integrity", "Availability"]

    // A threat may contain multiple expanded_control blocks
    // These blocks will be replacing the older "control" string or
    // "proposed_control" blocks

    expanded_control "control name" {
      description = "The control must have a description"

      // implemented is optional, but defaults to false
      implemented = true

      // implementation_notes are optional
      implementation_notes = "This string is optional"

      // risk_reduction, while optional, is recommended
      // this value takes an integer
      risk_reduction = 50

      // a control may contain optional attribute blocks
      attribute "Attribute Name" {
        value = "This value string must be set though for each attribute"
      }

      // a good use for these may be to refer to OWASP URLs
      attribute "OWASP Proactive Control" {
        value = "<link to control>"
      }
    }

    // WARNING: The "control" string value is going to be deprecated in
    // favor of expanded_control block!

    // The control is optional, and allows the author to capture controls
    // or circumstances that may reduce the likelihood of impact of the threat
    // control = "We require 2FA for access"

    // The stride is an optional array of STRIDE elements that apply to this threat
    // The available values are:
    // Spoofing
    // Tampering
    // Repudiation
    // Info Disclosure
    // Denial Of Service
    // Elevation Of Privilege
    stride = ["Spoofing", "Tampering", "Repudiation", "Info Disclosure", "Denial Of Service", "Elevation Of Privilege"]

    // The information_asset_refs are an optional array of information_assets
    // the elements must much existing information_assets - as above
    information_asset_refs = ["cred store"]

    // WARNING: The "proposed_control" blocks are going to be deprecated in
    // favor of expanded_control blocks!

    // The proposed_control blocks are optional, and are used to track 
    // proposed controls
    // proposed_control {
      // The Description is required
      // description = "This is a proposed control"

      // The implemented boolean is optional, and defaults to false
      // implemented = true
    // }
  } // End of threat block

  // You can import an external .hcl file that includes control descriptions
  // Remember to do this at the threatmodel block level
  // Similar to the "including" block, this can be a remote file too

  // An example of what may be in controls.hcl:
  //
  // spec_version = "0.1.9"
  // component "control" "control_name" {
  //   description = "A control that can be used in multiple places"
  // }

  imports = ["controls.hcl"]

  threat {

    // To reference the above component
    expanded_control "Control Name" {
      description = import.control.control_name.description
      risk_reduction = 50
    }

    description = <<EOT
Descriptions may be a multi-line entry as well.

For example, this is still part of the threat description
EOT
  }

  // Each threatmodel may contain a single data_flow_diagram
  // This format will be deprecated in the future ^

  // As of 0.1.6 threatmodels may contain multiple data_flow_diagram_v2 blocks
  // The data_flow_diagram_v2 is a HCL representation of a data flow diagram
  // You can read more about security DFDs here https://docs.microsoft.com/en-us/learn/modules/tm-create-a-threat-model-using-foundational-data-flow-diagram-elements/

  data_flow_diagram_v2 "level 0 diagram" {

    // All blocks must have unique names
    // That means that a process, data_store, or external_element can't all
    // be named "foo"

    process "update data" {}

    // All these elements may include an optional trust_zone
    // Trust Zones are used to define trust boundaries

    process "update password" {
      trust_zone = "secure zone"
    }

    data_store "password db" {
      trust_zone = "secure zone"

      // data_store blocks can refer to an information_asset from the
      // threatmodel
      information_asset = "cred store"
    }

    external_element "user" {}

    // To connect any of the above elements, you use a flow block
    // Flow blocks can have the same name, but their from and to fields
    // must be unique

    flow "https" {
      from = "user"
      to = "update data"
    }

    flow "https" {
      from = "user"
      to = "update password"
    }

    flow "tcp" {
      from = "update password"
      to = "password db"
    }

    // You can also define Trust Zones at the data_flow_diagram level

    trust_zone "public zone" {

      // Within a trust_zone you can then include processes, data_stores
      // or external_elements

      // Make sure that either you omit the element's trust_zone, or that it
      // matches

      process "visit external site" {}

      external_element "OIDC Provider" {}

    }
  }
}

