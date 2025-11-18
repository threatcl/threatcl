# threatcl

Threat Modeling with HCL

## What happened to hcltm?

hcltm has been renamed to `threatcl`. Welcome!

## Overview

> [!TIP]
> Want to read the new documentation? Head over to [threatcl.github.io](https://threatcl.github.io/)

There are many different ways in which a threat model can be documented. From a simple text file, to more in-depth word documents, to fully instrumented threat models in a centralised solution. Two of the most valuable attributes of a threat model are being able to clearly document the threats, and to be able to drive valuable change.

`threatcl` aims to provide a DevOps-first approach to documenting a [system threat model](https://owasp.org/www-community/Threat_Modeling) by focusing on the following goals:

- Simple text-file format
- Simple cli-driven user experience
- Integration into version control systems (VCS)

This repository is the home of the `threatcl` cli software. The `threatcl` [spec](spec.hcl) is based on [HCL2](https://github.com/hashicorp/hcl/tree/hcl2), HashiCorp's Configuration Language, which aims to be "_pleasant to read and write for humans, and a JSON-based variant that is easier for machines to generate and parse_". The `threatcl` spec lives at [github.com/threatcl/spec](https://github.com/threatcl/spec). Combining the `threatcl` cli software and the `threatcl` spec allows practitioners to define a system threat model in HCL, for example:

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

    expanded_control "Guards" {
      description = "Trained guards patrol tower"
      risk_reduction = 75
    }
  }

  data_flow_diagram_v2 "dfd name" {
    // ... see below for more information
  }

}
```

See [Data Flow Diagram](#data-flow-diagram) for more information on how to construct data flow diagrams that may be converted to PNGs automatically.

To see an example of how to reference pre-defined control libraries for the [OWASP Proactive Controls](https://owasp.org/www-project-proactive-controls/) and [AWS Security Checklist](https://d1.awsstatic.com/whitepapers/Security/AWS_Security_Checklist.pdf) see [examples/tm3.hcl](examples/tm3.hcl). We also have the [MITRE ATT&CK Controls](https://attack.mitre.org/mitigations/enterprise/) [here](examples/MITRE_ATTACK_controls.hcl).

You can also include an external threatmodel into your own, to reference and use all its information. You can see [examples/including-example/corp-app.hcl](examples/including-example/corp-app.hcl) as an example.

To see a full description of the spec, see [here](spec.hcl) or run:

```bash
threatcl generate boilerplate
```

`threatcl` will also process JSON files, but the only caveat is that import modules and variables won't work. You can see [examples/tm1.json](examples/tm1.json) as an example.

## Why HCL?

HCL is the primary configuration language used in the products by HashiCorp, in-particularly, [Terraform](https://www.terraform.io/) - their open-source Infrastructure-as-Code software. I worked at HashiCorp for a while and the language really grew on me, plus, if DevOps and Software engineers are using the language, then simplifying how they document threat models aligns with `threatcl`'s goals.

You can use `threatcl` with JSON, but you lose some of the features. For more, see the [examples/](examples/) folder.

## Why not just document them in MD?

I liked the idea of using a format that could be programmatically interacted with.

## Kudos and References

One of the features of `threatcl` is the automatic generation of [data flow diagrams](#data-flow-diagram) from HCL files. This leverages the [go-dfd](https://github.com/marqeta/go-dfd) package by Marqeta and [Blake Hitchcock](https://github.com/rbhitchcock). Definitely check out their blog post on [Threat models at the speed of DevOps](https://community.marqeta.com/t5/engineering-blogs/threat-models-at-the-speed-of-devops/ba-p/40).

Additionally I'd like to extend thanks to [Jamie Finnigan](https://twitter.com/chair6) and [Talha Tariq](https://twitter.com/0xtbt) at HashiCorp for allowing me to continue working on this open-source tool even after I'd finished up with HashiCorp.

Also thanks to the IriusRisk folks for the [OpenThreatModel specification](https://github.com/iriusrisk/OpenThreatModel).

# threatcl cli

## Installation

Download the latest version from [releases](https://github.com/threatcl/threatcl/releases) and move the `threatcl` binary into your PATH.

## Install with Homebrew

The following will add a local tap, and install `threatcl` with [Homebrew](https://brew.sh/)

```bash
brew install threatcl/repo/threatcl
```

## Run with Docker

```bash
docker run --rm -it ghcr.io/threatcl/threatcl:latest
```

## Run with GitHub Actions

`threatcl` can be integrated directly into your GitHub repos with https://github.com/threatcl/threatcl-action. This is one of the ideal methods to manage your threat models, and helps meet the goal of integrating into your version control systems.

## Building from Source

1. Clone this repository.
2. Change into the directory, `threatcl`
3. `make bootstrap`
4. `make build`

For further help on contributing to `threatcl` please see the [CHANGELOG.md](CHANGELOG.md).

## Usage

For help on any subcommands use the `-h` flag.

```bash
$ threatcl
Usage: threatcl [--version] [--help] <command> [<args>]

Available commands are:
    dashboard    Generate markdown files from existing HCL threatmodel file(s)
    dfd          Generate Data Flow Diagram PNG or DOT files from existing HCL threatmodel file(s)
    export       Export threat models into other formats
    generate     Generate an HCL Threat Model
    list         List Threatmodels found in HCL file(s)
    mcp          Model Context Protocol (MCP) server for threatcl
    query        Execute GraphQL queries against threat model data
    server       Start a GraphQL API server for threat models
    terraform    Parse output from 'terraform show -json'
    validate     Validate existing HCL Threatmodel file(s)
    view         View existing HCL Threatmodel file(s)
```

## (Optional) Config file

Most of the `threatcl` commands have a `-config` flag that allows you to specify a `config.hcl` file. HCL within this file may be used to overwrite some of `threatcl`'s default attributes. These are listed below:

- **Initiative Sizes** - defaults to "Undefined", "Small", "Medium", "Large"
- **Default Initiative Size** - defaults to "Undefined
- **Information Classifications** - defaults to "Restricted", "Confidential", "Public"
- **Default Information Classification** - defaults to "Confidential"
- **Impact Types** - defaults to "Confidentiality", "Integrity", "Availability"
- **STRIDE Elements** - defaults to "Spoofing", "Tampering", "Info Disclosure", "Denial Of Service", "Elevation Of Privilege"
- **Uptime Dependency Classifications** - defaults to "none", "degraded", "hard", "operational"
- **Default Uptime Depency Classification** - defaults to "none"

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

The `threatcl list` and `threatcl view` commands can be used to list and view data from `threatcl` spec HCL files.

```bash
$ threatcl list examples/*
#  File              Threatmodel      Author
1  examples/tm1.hcl  Tower of London  @xntrik
2  examples/tm1.hcl  Fort Knox        @xntrik
3  examples/tm2.hcl  Modelly model    @xntrik
```

## Validate

The `threatcl validate` command is used to validate a `threatcl` spec HCL file.

```bash
$ threatcl validate examples/*
Validated 3 threatmodels in 3 files
```

## Export

The `threatcl export` command is used to export a `threatcl` threat model (or models) into the native JSON representation (by default), or into the [OTM](https://github.com/iriusrisk/OpenThreatModel) json representation, or even back into `hcl` (Which is useful to output fresh HCL from dynamic threat models). You can also directly save them into a file with the `-output` flag.

```bash
$ threatcl export -format=otm examples/tm1.hcl
[{"assets":[{"description":"including the imperial state crown","id":"crown-jewels","name":"crown jewels","risk":{"availability":0,"confidentiality":0,"integrity":0}}],"mitigations":[{"attributes":{"implementation_notes":"They are trained to be guards as well","implemented":true},"description":"Lots of guards patrol the area","id":"lots-of-guards","name":"Lots of Guards","riskReduction":80}],"otmVersion":"0.2.0","project":{"attributes":{"initiative_size":"Small","internet_facing":true,"network_segment":"dmz","new_initiative":true},"description":"A historic castle","id":"tower-of-london","name":"Tower of London","owner":"@xntrik"},"threats":[{"categories":["Confidentiality"],"description":"Someone who isn't the Queen steals the crown","id":"threat-1","name":"Threat 1","risk":{"impact":0,"likelihood":null}}]},{"assets":[{"description":"Lots of gold","id":"gold","name":"Gold","risk":{"availability":0,"confidentiality":0,"integrity":0}}],"mitigations":[{"attributes":{"implemented":true},"description":"A large wall surrounds the fort","id":"big-wall","name":"Big Wall","riskReduction":80}],"otmVersion":"0.2.0","project":{"attributes":{"initiative_size":"Small","internet_facing":true,"new_initiative":false},"description":"A .. fort?","id":"fort-knox","name":"Fort Knox","owner":"@xntrik"},"threats":[{"categories":["Confidentiality"],"description":"Someone steals the gold","id":"threat-1","name":"Threat 1","risk":{"impact":0,"likelihood":null}}]}]
```

## Generate

The `threatcl generate` command is used to either output a generic `boilerplate` `threatcl` spec HCL file, or, interactively ask the user questions to then output a `threatcl` spec HCL file.

### Generate Interactive

See the following example of:

```bash
threatcl generate interactive
```

<p align="center">
  <img width="600" src="https://xntrik.wtf/hcltm.svg" />
</p>

### Generate Interactive Editor

If you prefer to work directly in your `$EDITOR` then run:

```bash
threatcl generate interactive editor
```

This will open your editor with a barebones HCL threat model. If you want to validate the model after creation, then use the `-validate` flag.

## MCP

The `threatcl mcp` command exposes a local [MCP](https://modelcontextprotocol.io/introduction) server so that you can interact with threatcl hcl files via an MCP Host, for instance AI/LLM applications such as [Claude Desktop](https://claude.ai/download), [Cursor](https://www.cursor.com/), or any other applications that support MCP.

The command takes a single, optional argument, `-dir=<path>` which allows additional MCP Tools to interact with files within that path. Without this setting, the MCP Tools can interact with strings, but will rely on other mechanisms within the MCP Host to interact with the underlying filesystem.

It's fair to say that this functionality is pretty beta at the moment.

## Server (GraphQL API)

The `threatcl server` command starts a GraphQL API server that exposes your threat models via HTTP for programmatic querying and integration.

### Basic Usage

```bash
# Start the server
$ threatcl server -dir ./examples

# With file watching for auto-reload
$ threatcl server -dir ./examples -watch

# Custom port
$ threatcl server -dir ./examples -port 3000
```

Navigate to `http://localhost:8080` to access the interactive GraphQL Playground.

### Example Query

```graphql
query {
  stats {
    totalThreatModels
    totalThreats
    implementedControls
  }

  threatModels(filter: { internetFacing: true }) {
    name
    threats {
      description
      controls {
        name
        implemented
      }
    }
  }
}
```

### Documentation

For complete API documentation, schema reference, advanced queries, and integration examples, see:
- **Full API Documentation**: [docs/graphql-api.md](docs/graphql-api.md)
- **Query Examples**: [examples/graphql-queries.md](examples/graphql-queries.md)

## Query (GraphQL CLI)

The `threatcl query` command executes GraphQL queries directly from the command line without starting a server. This is ideal for automation, CI/CD pipelines, and shell scripting.

### Basic Usage

```bash
# Get statistics
$ threatcl query -dir ./examples -query '{ stats { totalThreats } }'

# Query from file
$ threatcl query -dir ./examples -file queries/get-stats.graphql

# Use in scripts
$ THREATS=$(threatcl query -dir ./examples \
    -query '{ stats { totalThreats } }' \
    -output compact | jq -r '.data.stats.totalThreats')
$ echo "Found $THREATS threats"
```

### Output Formats

- `pretty` (default): Formatted JSON with indentation
- `json`: Same as pretty
- `compact`: Single-line JSON for scripting

### Query with Variables

```bash
$ threatcl query -dir ./examples \
    -query 'query($author: String) { threatModels(filter: {author: $author}) { name } }' \
    -vars '{"author": "John Doe"}'
```

### CI/CD Example

```bash
#!/bin/bash
# Check if all controls are implemented before deployment

UNIMPLEMENTED=$(threatcl query -dir ./threatmodels \
  -query '{ stats { totalControls implementedControls } }' \
  -output compact | jq -r '.data.stats.totalControls - .data.stats.implementedControls')

if [ "$UNIMPLEMENTED" -gt 0 ]; then
  echo "ERROR: $UNIMPLEMENTED controls are not yet implemented"
  exit 1
fi

echo "All controls implemented, proceeding with deployment"
```

See [docs/graphql-api.md](docs/graphql-api.md) for available queries and the GraphQL schema.

## Dashboard

The `threatcl dashboard` command takes `threatcl` spec HCL files, and generates a number of markdown and png files, dropping them into a selected folder.

```bash
$ threatcl dashboard -overwrite -outdir=dashboard-example examples/*
Created the 'dashboard-example' directory
Writing dashboard markdown files to 'dashboard-example' and overwriting existing files
Successfully wrote to 'dashboard-example/tm1-toweroflondon.md'
Successfully wrote to 'dashboard-example/tm1-fortknox.md'
Successfully wrote to 'dashboard-example/tm2-modellymodel.png'
Successfully wrote to 'dashboard-example/tm2-modellymodel.md'
Successfully wrote to 'dashboard-example/dashboard.md'
```

### Custom Markdown Templates

The `threatcl dashboard` command can also take optional flags to specify custom templates (as per Golang's [text/template](https://pkg.go.dev/text/template)).

To specify a dashboard template file, use the `-dashboard-template` flag. For an example, see [dashboard-template.tpl](examples/dashboard-template.tpl).

To specify a threatmodel template file, use the `-threatmodel-template` flag. For an example, see [threatmodel-template.tpl](examples/threatmodel-template.tpl).

### Custom Filename for the Dashboard Index file

The `threatcl dashboard` command can also take an optional flag to specify a filename for the "index" generated dashboard file. By default this file is `dashboard.md`. Use the `-dashboard-filename` flag without an extension to change this filename.

## Data Flow Diagram

As per the [spec](spec.hcl), a `threatmodel` may include `data_flow_diagram_v2` blocks. An example of a simple DFD is available [here](examples/tm2.hcl). The old, single-use-block `data_flow_diagram` will be deprecated at some point, so it's better to use `data_flow_diagram_v2` named blocks, that way you can have multiple associated DFDs.

The `threatcl dfd` command takes `threatcl` spec HCL files, and generates a number of png files, dropping them into a selected folder.

If the HCL file doesn't include a `threatmodel` block with a `data_flow_diagram` or `data_flow_diagram_v2` block, then nothing is output.

The command itself is very similar to the Dashboard command.

```bash
$ threatcl dfd -overwrite -outdir testout examples/*
Successfully created 'testout/tm2-modellymodel.png'
```

If your `threatmodel` doesn't include a `diagram_link`, but does include a `data_flow_diagram`, then this will also be rendered when running `threatcl dashboard`.

## Terraform

The `threatcl terraform` command is able to extract data resources from the `terraform show -json` [docs here](https://www.terraform.io/docs/cli/commands/show.html) output of plan files, or active state files, and convert these into drafted `information_asset` blocks for inclusion in `threatcl` files.

If you're in a folder with existing state, you can execute the following:

```bash
terraform show -json | threatcl terraform -stdin
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
terraform show -json <plan-file> | threatcl terraform -stdin
```

If you want to update an existing `threatcl` threat model file ("threatmodel.hcl") you can with:

```bash
terraform show -json <plan> | threatcl terraform -stdin -add-to-existing=threatmodel.hcl > new-threatmodel.hcl
```

With the `-add-to-existing` flag, you can also specify `-tm-name=<string>` if you need to specify a particular threat model from the source file, if there are multiple. And you can also apply a default classification, with the `-default-classification=Confidential` flag.

These commands can also take a file as input too, in which case, omit the `-stdin` flag.

The terraform resources that `threatcl` is aware of are hard coded in [pkg/terraform/terraform.go](pkg/terraform/terraform.go). If you want the `threatcl terraform` command to output other `information_asset` resources that aren't in there, you can supply your own version of this json via the `-tf-collection=<json file>` flag.
