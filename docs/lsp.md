# threatcl LSP (Language Server)

`threatcl lsp` runs a [Language Server Protocol](https://microsoft.github.io/language-server-protocol/)
server over stdio, giving any LSP-capable editor live language intelligence for
threatcl HCL threat models:

- **Diagnostics** — syntax errors, unknown blocks/attributes, missing required
  attributes, and invalid enum values (e.g. an unrecognised risk `likelihood`),
  pushed on every edit.
- **Completion** — context-aware blocks, attributes, and enum values. Block
  completions expand to a snippet scaffold with the braces and labels.
- **Hover** — documentation for the block type or attribute under the cursor.
- **Document symbols** — an outline of the threat models, threats, controls,
  information assets, and data flow diagrams in the file.
- **Formatting** — canonical `hclwrite` formatting (the same lexical formatting
  `terraform fmt` uses), suitable for format-on-save.

The server talks LSP over **stdin/stdout**; log output goes to stderr (or a
`-log` file). It is launched by your editor's LSP client, not run by hand.

```
Usage: threatcl lsp [options]

 -config=<file>   Optional config file (see "Known limitations" below)
 -log=<file>      Optional log file for server diagnostics (default: stderr)
 -stdio           Communicate over stdio (default and only transport)
```

## A note on `.hcl` and filetypes

threatcl files use the `.hcl` extension, which collides with Terraform, Packer,
and other HCL dialects. If you also use a Terraform/HCL language server, a plain
`*.hcl` match will start **both** servers on the same buffer.

Two ways to avoid the clash, in order of preference:

1. **Name threatcl files `*.tm.hcl`** and match on that suffix. This is the
   cleanest separation and the convention these examples use.
2. **Scope the threatcl client to the project/workspace** (e.g. only start it
   when a known threat-model directory is the root), so it doesn't attach in
   unrelated Terraform projects.

## Editor wiring

There is no published editor extension yet; the examples below use each editor's
generic LSP client. `threatcl` must be on your `PATH`.

### Neovim (0.8+)

Using the built-in client, started by an autocommand for the chosen pattern:

```lua
vim.api.nvim_create_autocmd({ "BufRead", "BufNewFile" }, {
  pattern = "*.tm.hcl",
  callback = function(args)
    vim.lsp.start({
      name = "threatcl",
      cmd = { "threatcl", "lsp" },
      root_dir = vim.fs.dirname(args.file),
    })
  end,
})
```

If you prefer to keep treating the buffer as `hcl` for syntax highlighting,
that's fine — the `name`/`cmd` above are independent of the filetype. Just be
aware that a `*.hcl`-wide pattern will also attach to Terraform files.

### Helix

In `languages.toml`, define a language server and bind it to a language whose
`file-types` is scoped to the threatcl suffix:

```toml
[language-server.threatcl]
command = "threatcl"
args = ["lsp"]

[[language]]
name = "threatcl"
scope = "source.hcl"
file-types = [{ glob = "*.tm.hcl" }]
roots = []
language-servers = ["threatcl"]
```

### VS Code

There is no Marketplace extension yet. The eventual path is a thin
generic-LSP-client extension that launches `threatcl lsp`. Until then you can use
a generic LSP bridge extension and point its server command at
`threatcl lsp`, scoping it to `*.tm.hcl`.

There is an early dev version of this being worked on in the editors folder

### Zed

A small Zed extension pointing at `threatcl lsp` is the supported path; it is not
published yet.

## Known limitations

These are deliberate scoping decisions for the first release, not bugs:

- **`-config` does not affect the language server.** Diagnostics and completion
  use threatcl's built-in spec enum defaults. A `-config` / `.hcltmrc` override
  (custom information classifications, initiative sizes, etc.) is **not** yet
  applied to LSP results. The flag is accepted and validated, but the override
  isn't threaded through. This will be lifted once the language layer grows a
  config-aware schema.
- **Some validations aren't surfaced.** Duplicate names, `information_asset_ref`
  existence, and data-flow-diagram wiring are validated by `threatcl validate`
  but are not reported as ranged diagnostics here, because those errors are keyed
  on names rather than source positions.
- **Full-document sync.** The server re-reads the whole document on each change.
  This is comfortably fast for threat-model-sized files; incremental sync is
  deferred.
- **No go-to-definition / references / rename / semantic tokens yet.** These are
  planned follow-ups (e.g. jumping between a `control_import` and its component,
  or an `information_asset_ref` and its asset).
