# hcltm

Threat Modeling with HCL

## Overview

There are many different ways in which a threat model can be documented. From a simple text file, to more in-depth word documents, to fully instrumented threat models in a centralised solution. Two of the most valuable attributes of a threat model are being able to clearly document the threats, and to be able to drive valuable change. 

`hcltm` aims to provide a DevOps-first approach to documenting a [system threat model](https://owasp.org/www-community/Threat_Modeling) by focusing on the following goals:

* Simple text-file format
* Simple cli-driven user experience
* Integration into version control systems (VCS)

This repository is the home of the `hcltm` cli software. The `hcltm` [spec](spec.hcl) is based on [HCL2](https://github.com/hashicorp/hcl/tree/hcl2), HashiCorp's Configuration Language, which aims to be "_pleasant to read and write for humans, and a JSON-based variant that is easier for machines to generate and parse_". Combining the `hcltm` cli software and the `hcltm` spec allows practitioners to define a system threat model in HCL, for example:

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

See [Data Flow Diagram](#data-flow-diagram) for more information on how to construct data flow diagrams that are converted to PNGs automatically.

To see an example of how to reference pre-defined control libraries for the [OWASP Proactive Controls](https://github.com/OWASP/www-project-proactive-controls/tree/7622bebed900a6a5d7b7b9b01fb3fe2b0e695545/v3/en) and [AWS Security Checklist](https://d1.awsstatic.com/whitepapers/Security/AWS_Security_Checklist.pdf) see [examples/tm3.hcl](examples/tm3.hcl)

To see a full description of the spec, see [here](spec.hcl) or run:

```bash
hcltm generate boilerplate
```

`hcltm` will also process JSON files, but the only caveat is that import modules and variables won't work. You can see [examples/tm1.json](examples/tm1.json) as an example.

## Why HCL?

HCL is the primary configuration language used in the products by HashiCorp, in-particularly, [Terraform](https://www.terraform.io/) - their open-source Infrastructure-as-Code software. I worked at HashiCorp for a while and the language really grew on me, plus, if DevOps and Software engineers are using the language, then simplifying how they document threat models aligns with `hcltm`'s goals.

You can use `hcltm` with JSON, but you lose some of the features. For more, see the [examples/](examples/) folder.

## Why not just document them in MD?

I liked the idea of using a format that could be programmatically interacted with.

## Kudos and References

One of the features of `hcltm` is the automatic generation of [data flow diagrams](#data-flow-diagram) from HCL files. This leverages the [go-dfd](https://github.com/marqeta/go-dfd) package by Marqeta and [Blake Hitchcock](https://github.com/rbhitchcock). Definitely check out their blog post on [Threat models at the speed of DevOps](https://community.marqeta.com/t5/engineering-blogs/threat-models-at-the-speed-of-devops/ba-p/40).

Additionally I'd like to extend thanks to [Jamie Finnigan](https://twitter.com/chair6) and [Talha Tariq](https://twitter.com/0xtbt) at HashiCorp for allowing me to continue working on this open-source tool even after I'd finished up with HashiCorp.

# hcltm cli

## Installation

Download the latest version from [releases](https://github.com/xntrik/hcltm/releases) and move the `hcltm` binary into your PATH.

## Install with Homebrew

The following will add a local tap, and install `hcltm` with [Homebrew](https://brew.sh/)

```bash
brew install xntrik/repo/hcltm
```

## Run with Docker

```bash
docker run --rm -it xntrik/hcltm
```

## Run with GitHub Actions

`hcltm` can be integrated directly into your GitHub repos with https://github.com/xntrik/hcltm-action. This is one of the ideal methods to manage your threat models, and helps meet the goal of integrating into your version control systems.

## Building from Source

1. Clone this repository.
2. Change into the directory, `hcltm`
3. `make bootstrap`
4. `make dev`

For further help on contributing to `hcltm` please see the [CHANGELOG.md](CHANGELOG.md).

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

```hcl
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

### Generate Interactive

See the following example of:

```bash
hcltm generate interactive
```

<p align="center">
  <img width="600" src="https://xntrik.wtf/hcltm.svg" />
</p>

### Generate Interactive Editor

If you prefer to work directly in your `$EDITOR` then run:

```bash
hcltm generate interactive editor
```

This will open your editor with a barebones HCL threat model. If you want to validate the model after creation, then use the `-validate` flag.

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

### Custom Markdown Templates

The `hcltm dashboard` command can also take optional flags to specify custom templates (as per Golang's [text/template](https://pkg.go.dev/text/template)).

To specify a dashboard template file, use the `-dashboard-template` flag. For an example, see [dashboard-template.tpl](examples/dashboard-template.tpl).

To specify a threatmodel template file, use the `-threatmodel-template` flag. For an example, see [threatmodel-template.tpl](examples/threatmodel-template.tpl).

### Custom Filename for the Dashboard Index file

The `hcltm dashboard` command can also take an optional flag to specify a filename for the "index" generated dashboard file. By default this file is `dashboard.md`. Use the `-dashboard-filename` flag without an extension to change this filename.

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

## Terraform

The `hcltm terraform` command is able to extract data resources from the `terraform show -json` [docs here](https://www.terraform.io/docs/cli/commands/show.html) output of plan files, or active state files, and convert these into drafted `information_asset` blocks for inclusion in `hcltm` files.

If you're in a folder with existing state, you can execute the following:

```bash
terraform show -json | hcltm terraform -stdin
```

This will output something similar to this:

```bash
information_asset "aws_rds_cluster default" {
  description                = "cluster_identifier: aurora-cluster-demo, database_name: mydb"
  information_classification = ""
  source                     = "terraform state"
}
information_asset "aws_s3_bucket example" {
  description                = "bucket: terraform-20211107232017071500000001"
  information_classification = ""
  source                     = "terraform state"
}
```

You can also see similar output from a plan file that hasn't yet been applied with Terraform by running:

```bash
terraform show -json <plan-file> | hcltm terraform -stdin
```

If you want to update an existing `hcltm` threat model file ("threatmodel.hcl") you can with:

```bash
terraform show -json <plan> | hcltm terraform -stdin -add-to-existing=threatmodel.hcl > new-threatmodel.hcl
```

With the `-add-to-existing` flag, you can also specify `-tm-name=<string>` if you need to specify a particular threat model from the source file, if there are multiple. And you can also apply a default classification, with the `-default-classification=Confidential` flag.

These commands can also take a file as input too, in which case, omit the `-stdin` flag.
