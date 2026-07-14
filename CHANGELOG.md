## 0.6.1

### Jul 14, 2026

CHANGES:

* Bumped to `spec` `0.6.0`. The multi-file commands (`validate`, `list`, `view`,
  `dfd`, `mermaid`, `export`, `dashboard`) now parse all discovered `.hcl` files
  together as one *set* (via the new `ParseHCLRawSet`), so a `threatmodel` can
  `extends` a parent declared in a different file - previously each file was
  parsed on its own and a cross-file `extends` target failed to resolve.
* BEHAVIOR CHANGE: because those files are now parsed as one set, `threatmodel`
  names and ids must be unique across the whole set of `.hcl` files being
  processed. Previously the same name could appear in separate files and each
  was listed independently; a collision is now a parse error that names the
  offending files. `.json` threat models are still parsed individually (the
  spec set parser is HCL-only), so they keep their prior behavior.
* The `backend` block's `segment` attribute was removed in `spec` `0.6.0`;
  `segment = "..."` in a `backend` block is now a parse error.

## 0.6.0

### Jul 9, 2026

CHANGES:

* Added invariants: org-wide, machine-checked rules evaluated against threat models via `threatcl validate -invariants=<file>`. Invariants live in their own HCL file, target a collection within each model (`threat`, `control`, DFD `process`/`flow`, ...), and express conditions as native HCL expressions with `item`/`tm`/`dfd` in scope. They support `error`/`warning` severities, `when` filters, interpolated `error_message`s, and per-model exemptions with justifications. Exemptions reference models as objects — by display name (`threatmodel["Tower of London"]`) or by dotted identifier (`threatmodel.tower_of_london`, `threatmodel.buildings.tower` for nested ids, with parent models addressable at the namespace itself) — and dangling references fail loudly. See [docs/invariants.md](docs/invariants.md).
* Bumped to `spec` `0.5.2`, which introduces optional `id` and `extends` attributes on `threatmodel` blocks (namespaced identifiers and explicit inheritance), identifier-safe slug / dot-notation element references inside models, and disables remote `imports`/`including` fetches unless `allow_remote_imports = true` is set in the threatcl config. Go toolchain bumped to 1.26.5 to match.

## 0.5.2

### Jun 28, 2026

CHANGES:

* Bumped to `spec` `0.4.0`, which introduces an optional `segment` attribute to the `backend` block
* Also bumped numerous dependencies
* Re-released CI workflow

## 0.5.1

### Jun 16, 2026

CHANGES:

* Added a new `threatcl mermaid` command that outputs the raw mermaid source from `mermaid` blocks in your HCL threat models. Similar to `threatcl dfd`, it defaults to STDOUT (so it can be piped into renderers such as `mmdc`), and also supports `-out`, `-outdir`, and `-index`. It does not render images itself.

## 0.5.0

### Jun 14, 2026

CHANGES:

* Bumped threatcl to support the 0.3.1 version of the spec, this brings a number of changes
    * `threatmodel` block now includes an optional `repository` attribute (array of strings)
    * `threat` blocks now support optional `risk` blocks
* Added a new `threatcl lsp` command that runs a Language Server (LSP) over stdio, providing diagnostics, completion, hover, document symbols, and formatting for threatcl HCL threat models in LSP-capable editors. See [docs/lsp.md](docs/lsp.md) for editor wiring and current limitations.
* Built on the new `lang` language-intelligence layer in `spec`.

## 0.4.14

### Jun 7, 2026

CHANGES:

* Minor tweak to inverse the diff presented in `cloud validate -diff`

## 0.4.13

### Jun, 6, 2026

CHANGES:

* Support for `spec` 0.2.8, which brings mermaid support
* Adjusted OTM export, the graphql local server, and boilerplate to support mermaid blocks

## 0.4.12

### May 30, 2026

CHANGES:

* Bumped to `spec` 0.2.7 - now supports information_asset ref attributes
* Tidied up some of the cloud commands
* Introduced new cloud library commands associated with asset refs
* Adjusted other cloud commands to support as well
* Added `-diff` flag to `cloud validate`

## 0.4.11

### May 24, 2026

CHANGES:

* Bumped to `spec` 0.2.6
* Introduced `cloud export` command

## 0.4.10

### May 19, 2026

CHANGES:

* Minor bump to CI to release linux / arm binary

## 0.4.9

### May 16, 2026

CHANGES:

* Bumping to support `spec` 0.2.5
* New `protocol` optional attribute inside of dfd flow's
* New `dfd` cli flags to support optional rendering for flow protocols
* New `dfd` cli flags to support outputting in mermaid or d2 text formats

## 0.4.8

### May 5, 2026

CHANGES:

* Minor adjustment to dev bootstrap dependencies

## 0.4.7

### Apr 12, 2026

CHANGES:

* Adjusted default API endpoint for `threatcl cloud` commands

## 0.4.6

### Apr 10, 2026

CHANGES:

* Cloud `threatcl cloud threatmodel` command now fetches model URL

## 0.4.5

### Apr 9, 2026

CHANGES:

* Bumped a bunch of dependencies

## 0.4.4

### Mar 24, 2026

CHANGES:

* Improved auto-completion - thanks Kabir!
* Added Cloud Policy commands
* Other dependency bumps

## 0.4.3

### Feb 24, 2026

CHANGES:

* Added `cloud view -model-id` mode

## 0.4.2

### Feb 11, 2026

CHANGES:

* Added `cloud library export` and `cloud library import` commands

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

