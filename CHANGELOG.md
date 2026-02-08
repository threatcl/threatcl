## 0.4.1

### Feb 8, 2026

CHANGES:

* Added API Token Env var for `cloud` commands

## 0.4.0

### Feb 7, 2026

CHANGES:

* Introduced the beta `cloud` commands

## 0.3.1

### Dec 26, 2025

CHANGES:

* Adjusted GraphQL to support unique `threat` names

## 0.3.0

### Dec 24, 2025

CHANGES:

* Bumped threatcl spec to a new minor version, 0.2.3, this brings a bunch of new features
    * You can now use `control` blocks instead of `expanded_control` blocks (this is recommended)
    * `threat` blocks now need a name, such as `threat "threat name" {`

## 0.2.8

### Nov 18, 2025

CHANGES:

* Added the `query` command to allow GraphQL queries from the Checklist

## 0.2.7

### Nov 15, 2025

CHANGES:

* Added the `server` command to expose a GraphQL API endpoint.
* Minor tweaks to the boilerplate generation too, now includes the `control_imports` examples

## 0.2.6

### Oct 14, 2025

CHANGES:

* None, version bump to fix ci/cd

## 0.2.5

### Oct 13, 2025

CHANGES:

* Minor updates to the `mcp` implementation
* We can now define more attributes of a control in a separate file and pull the reference in with `control_imports`

## 0.2.4

### May 29, 2025

CHANGES:

* New `mcp` tool added to support writing DFD PNG files

## 0.2.3
### May 26, 2025

CHANGES:

* Added `mcp` command

## 0.2.2
### Aug 16, 2024

CHANGES:

* Upgraded to threatcl/spec v0.1.10
* Added `export -format=hcl` flag

## 0.2.1
### Mar 9, 2024

CHANGES:

* Upgraded to threatcl/spec v0.1.9
* This is a minor change and doesn't actually change the spec at all

## 0.2.0
### Mar 4, 2024

CHANGES:

* Renamed hcltm to threatcl
* Moved to a new org at github

## 0.1.8
### Mar 3, 2024

CHANGES:

* Minor dependency bump

## 0.1.7
### Feb 29, 2024

CHANGES:

* Updating to Go 1.20
* Added `export` sub-command
* Added OTM support to the `export` sub-command
* Support for remote file inclusion with `go-getter`

## 0.1.6
### Mar 21, 2023

CHANGES:

* Updating to Go 1.19
* CI now builds Docker images locally in ghcr
* `hcltm` commands now support multiple DFDs per `threatmodel` block
* Spec now supports `additional_attribute` key/value blocks
* Spec now supports the legacy `data_flow_diagram` and multiple `data_flow_diagram_v2`

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

