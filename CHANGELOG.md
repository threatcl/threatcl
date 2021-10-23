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

