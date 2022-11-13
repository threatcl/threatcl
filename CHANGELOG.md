## 0.1.5
### Nov 13, 2022

CHANGES:

* Imports and Includes now use go-getter for accessing individual files. See https://github.com/xntrik/hcltm/issues/67
* We now have a preliminary constraints system that can be used to emit warnings (during `hcltm validate` if there are deprecated features being used
* Added `expanded_control` blocks to `threatmodel` blocks
* Added deprecation warnings for `control` strings and `proposed_control` blocks. These will be phased out eventually in favor of `expanded_control` blocks

## 0.1.4
### Nov 9, 2022

CHANGES:

* hcltm spec now allows a `threatmodel` to include another `threatmodel`. See https://github.com/xntrik/hcltm/issues/61

## 0.1.3
### Nov 5, 2022

CHANGES:

* `hcltm dashboard` now supports custom file extensions. Thanks @dvogel

## 0.1.2
### Oct 23, 2022

CHANGES:

* `hcltm terraform` now supports a number of data storing resources from Azure, GCP and AWS
* `hcltm terraform` now supports the `-tf-collection` flag for specifying other terraform resources for parsing
* Other minor changes and bug fixes

## 0.1.1
### Feb 12, 2022

CHANGES:

* Can now install with Homebrew
* Can parse Terraform output to auto generate information assets (currently just for AWS resources)
* Can output raw Graphviz DOT files of Data Flow Diagrams
* Can output SVG Data Flow Diagrams
* Changed some of the colouring of auto generated Data Flow Diagrams
* Can link Data Flow Datagram Data Stores back into the Threat Model's Information Asssets

## 0.1.0
### Oct 23, 2021

CHANGES:

* `hcltm generate interactive` now has an `editor` sub-command to open a HCL file into your editor for editing 
* Can now handle JSON input (with some caveats)
* Allow `proposed_control` blocks within a `threat` block in a `threatmodel`
* Addressed a dependabot issue - I think?
* Dashboard output can now generate HTML files
* DFDs can now have `trust_zone` blocks with other elements embedded within

## 0.0.6
### Sep 25, 2021

CHANGES:

* README now includes instructions for running with Docker, and a walk through of `hcltm generate interactive`
* `hcltm-action` is now available for GitHub Actions
* Dashboards can now have custom index and threatmodel template files
* The dashboard index filename can be changed
* The dfd command can now just spit out the first DFD PNG with a target name
* The list command now has a row for whether the threatmodel includes a dfd
* Added OWASP Proactive Controls and the AWS Security Checklist as pre-defined control HCL files

## 0.0.5
### Mar 9th, 2021

CHANGES:

* This is the same as the original upstream fork, so we're starting at version 0.0.5

