// Minimal development launcher for the threatcl language server.
//
// It spawns `threatcl lsp` (which must be on your PATH) over stdio and attaches
// VS Code's language client to it for any file recognised as the `threatcl`
// language (see the `contributes.languages` block in package.json).
//
// This is a throwaway dev harness for trying out `threatcl lsp`, not a published
// extension. Run it with F5 (see README.md).

const { LanguageClient, TransportKind } = require("vscode-languageclient/node");

let client;

function activate(context) {
  // Allow overriding the binary path via the THREATCL_BIN env var; default to
  // whatever `threatcl` resolves to on PATH.
  const command = process.env.THREATCL_BIN || "threatcl";

  const serverOptions = {
    command,
    args: ["lsp"],
    transport: TransportKind.stdio,
  };

  const clientOptions = {
    documentSelector: [{ scheme: "file", language: "threatcl" }],
    // Surface server stderr/logs in the "threatcl LSP" output channel.
    outputChannelName: "threatcl LSP",
  };

  client = new LanguageClient(
    "threatcl",
    "threatcl LSP",
    serverOptions,
    clientOptions,
  );

  client.start();
  context.subscriptions.push({ dispose: () => client && client.stop() });
}

function deactivate() {
  return client ? client.stop() : undefined;
}

module.exports = { activate, deactivate };
