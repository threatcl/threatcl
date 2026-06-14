# threatcl LSP — VS Code dev launcher

A throwaway VS Code extension for trying out `threatcl lsp` locally. It spawns
`threatcl lsp` over stdio and attaches VS Code's language client to it. This is a
dev harness, not a published extension.

## Prerequisites

- `threatcl` on your `PATH` (`threatcl lsp -help` should work).
- Node.js + npm (for `vscode-languageclient`).

## One-time setup

```sh
cd editors/vscode-threatcl-dev
npm install
```

## Run it

1. Open **this folder** (`editors/vscode-threatcl-dev`) in VS Code
   (File → Open Folder…).
2. Press **F5** (Run → Start Debugging). This opens a second VS Code window, the
   **Extension Development Host**, with the extension loaded.
3. In that new window, open `sample.tm.hcl` (or any `*.tm.hcl` / `*.hcl` file).

You should now get:

- **Diagnostics** — change `likelihood = "high"` to `likelihood = "nonsense"`;
  a red error appears. Add a `bogus_attr = "x"` line; a warning/error appears.
- **Completion** — inside a block, press `Ctrl+Space` for blocks/attributes; on
  the right-hand side of `likelihood = ` press `Ctrl+Space` for enum values.
- **Hover** — hover an attribute name like `author` or a block keyword like
  `threat`.
- **Outline** — the Outline view (and breadcrumbs) show the threatmodel →
  threat / control / information_asset tree.
- **Format** — right-click → Format Document (or `Shift+Alt+F`).

Server logs appear in the **Output** panel → "threatcl LSP" channel.

## Syntax highlighting

Highlighting is **separate** from the language server — it comes from the
TextMate grammar in `threatcl.tmLanguage.json` (contributed via
`contributes.grammars`), not from `threatcl lsp`. The grammar colors block types,
attribute names, strings (with `${...}` interpolation), heredocs, comments,
booleans, and numbers. (LSP-driven semantic-token highlighting is a possible
future addition; the server doesn't emit semantic tokens yet.)

If colors don't change after editing the grammar, reload the Extension
Development Host: `Cmd+Shift+P` → "Developer: Reload Window". To inspect what
scope is under the cursor, use `Cmd+Shift+P` → "Developer: Inspect Editor Tokens
and Scopes".

## Notes

- To point at a specific binary instead of `PATH`, set `THREATCL_BIN` in your
  environment before launching VS Code.
- This extension claims **all** `.hcl` files as the `threatcl` language. If you
  also have a Terraform/HCL extension installed in the dev host, narrow
  `contributes.languages[].extensions` in `package.json` to just `.tm.hcl`.
- `-config` overrides do not yet affect LSP results — see
  [../../docs/lsp.md](../../docs/lsp.md).
