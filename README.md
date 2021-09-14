# hcltm

Threat Modeling with HCL

## Overview

This repository is the home of the `hcltm` cli software. The `hcltm` [spec](spec.hcl) is based on [HCL2](https://github.com/hashicorp/hcl/tree/hcl2) and allows practitioners to define a system threat model in HCL, for example.

```hcl
threatmodel "Tower of London" {
  description = "A historic castle"
  author = "@xntrik"

  attributes {
    new_initiative = "true"
    internet_facing = "true"
    initiative_size = "Small"
  }

  information_asset "crown jewels" {
    description = "including the imperial state crown"
    information_classification = "Confidential"
  }

  usecase {
    description = "The Queen can fetch the crown"
  }

  third_party_dependency "community watch" {
    description = "The community watch helps guard the premise"
    uptime_dependency = "degraded"
  }

  threat {
    description = "Someone who isn't the Queen steals the crown"
    impacts = ["Confidentiality"]
    control = "Lots of guards"
  }

  data_flow_diagram {
    // ... see below for more information
  }

}
```

To see a full description of the spec, see [here](spec.hcl) or run `hcltm generate boilerplate`.

# hcltm cli

## Installation

Download the latest version from [releases](https://github.com/xntrik/hcltm/releases) and move the `hcltm` binary into your PATH.

## Building from Source

1. Clone this repository.
2. Change into the directory, `hcltm`
3. `$ make bootstrap`
4. `$ make dev`

## Usage

For help on any subcommands use the `-h` flag.

```bash
$ hcltm
Usage: hcltm [--version] [--help] <command> [<args>]

Available commands are:
    dashboard    Generate markdown files from existing HCL threatmodel file(s)
    dfd          Generate Data Flow Diagram PNG files from existing HCL threatmodel file(s)
    generate     Generate an HCL Threat Model
    list         List Threatmodels found in HCL file(s)
    validate     Validate existing HCL Threatmodel file(s)
    view         View existing HCL Threatmodel file(s)

```

## Config file

Most of the `hcltm` commands have a `-config` flag that allows you to specify a `config.hcl` file. HCL within this file may be used to overwrite some of `hcltm`'s default attributes. These are listed below:

* **Initiative Sizes** - defaults to "Undefined", "Small", "Medium", "Large"
* **Default Initiative Size** - defaults to "Undefined
* **Information Classifications** - defaults to "Restricted", "Confidential", "Public"
* **Default Information Classification** - defaults to "Confidential"
* **Impact Types** - defaults to "Confidentiality", "Integrity", "Availability"
* **STRIDE Elements** - defaults to "Spoofing", "Tampering", "Info Disclosure", "Denial Of Service", "Elevation Of Privilege"
* **Uptime Dependency Classifications** - defaults to "none", "degraded", "hard", "operational"
* **Default Uptime Depency Classification** - defaults to "none"

For example:

```
initiative_sizes = ["S", "M", "L"]
default_initiative_size = "M"
info_classifications = ["1", "2"]
default_info_classification = "1"
impact_types = ["big", "small"]
strides = ["S", "T"]
uptime_dep_classifications = ["N", "D"]
default_uptime_dep_classification = "N"
```

If you modify these attributes, you'll need to remember to provide the config file for other operations, as this may impact validation or dashboard creation.

## List and View

The `hcltm list` and `hcltm view` commands can be used to list and view data from `hcltm` spec HCL files.

```bash
$ hcltm list examples/*
#  File              Threatmodel      Author
1  examples/tm1.hcl  Tower of London  @xntrik
2  examples/tm1.hcl  Fort Knox        @xntrik
3  examples/tm2.hcl  Modelly model    @xntrik
```

## Validate

The `hcltm validate` command is used to validate a `hcltm` spec HCL file.

```bash
$ hcltm validate examples/*
Validated 3 threatmodels in 3 files
```

## Generate

The `hcltm generate` command is used to either output a generic `boilerplate` `hcltm` spec HCL file, or, interactively ask the user questions to then output a `hcltm` spec HCL file.

## Dashboard

The `hcltm dashboard` command takes `hcltm` spec HCL files, and generates a number of markdown and png files, dropping them into a selected folder.

```bash
$ hcltm dashboard -overwrite -outdir=dashboard-example examples/*
Created the 'dashboard-example' directory
Writing dashboard markdown files to 'dashboard-example' and overwriting existing files
Successfully wrote to 'dashboard-example/tm1-toweroflondon.md'
Successfully wrote to 'dashboard-example/tm1-fortknox.md'
Successfully wrote to 'dashboard-example/tm2-modellymodel.png'
Successfully wrote to 'dashboard-example/tm2-modellymodel.md'
Successfully wrote to 'dashboard-example/dashboard.md'
```

## Data Flow Diagram

As per the [spec](spec.hcl), a `threatmodel` may include a single `data_flow_diagram`. An example of a simple DFD is available [here](examples/tm2.hcl).

The `hcltm dfd` command takes `hcltm` spec HCL files, and generates a number of png files, dropping them into a selected folder.

If the HCL file doesn't include a `threatmodel` block with a `data_flow_diagram` block, then nothing is output.

The command itself is very similar to the Dashboard command.

```bash
$ hcltm dfd -overwrite -outdir testout examples/*
Successfully created 'testout/tm2-modellymodel.png'
```

If your `threatmodel` doesn't include a `diagram_link`, but does include a `data_flow_diagram`, then this will also be rendered when running `hcltm dashboard`.

## Automatic Releases

Git commit messages will be auto-converted into Release change log text based on these prefixes:

```
feat = 'Features',
fix = 'Bug Fixes',
docs = 'Documentation',
style = 'Styles',
refactor = 'Code Refactoring',
perf = 'Performance Improvements',
test = 'Tests',
build = 'Builds',
ci = 'Continuous Integration',
chore = 'Chores',
revert = 'Reverts',
```

From https://github.com/marvinpinto/actions/blob/f2f409029c432b82229a4eacb8a313bc09abf48e/packages/automatic-releases/src/utils.ts#L38-L50
