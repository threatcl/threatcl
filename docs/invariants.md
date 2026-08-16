# Invariants

Invariants are org-wide, machine-checked rules evaluated against your threat
models — things like "no public endpoints should be unauthenticated" or "all
internet-facing features must document audit logging". They live in their own
HCL file, separate from your threat models, so one rule set can govern an
entire fleet of models.

```bash
threatcl validate -invariants=invariants.hcl ./models/
```

This page covers the CLI: the flag, the output, and the exit codes. The
invariants **language** — the `invariant` block, its attributes, the targets,
exemptions, and the expression environment — is documented in the spec module,
which is where the parser and evaluator live:
[github.com/threatcl/spec `docs/invariants.md`][spec-docs]. The same evaluator
runs in Threatcl Cloud, so a rule means the same thing wherever it runs.

[spec-docs]: https://github.com/threatcl/spec/blob/main/docs/invariants.md

## Running invariants

`threatcl validate` first validates the threat model files as usual, then
evaluates every invariant against every validated model. Every model in the run
is in scope, so rules that reason about the fleet — and exemptions that name
another model — resolve against the whole set:

```bash
threatcl validate -invariants=invariants.hcl ./models/
```

`-invariants` also works with `-stdin` and `-stdinjson`; violations are
attributed to `STDIN`.

An invariants file looks like this:

```hcl
invariant "threats_have_implemented_controls" {
  description = "Every threat must have at least one implemented control"
  severity    = "error"
  target      = "threat"
  condition   = anytrue([for c in item.controls : c.implemented])
}
```

See the [language reference][spec-docs] for the full set of attributes,
targets, and functions.

## Output and exit codes

```
$ threatcl validate -invariants=invariants.hcl ./models/
Validated 4 threatmodels in 3 files
Invariant 'internet_facing_models_document_audit_logging' exempts threatmodel 'Legacy Public API' (models/legacy.hcl): Grandfathered until Q3 migration; tracked in SEC-123
Invariant violation [error] 'threats_have_implemented_controls': threat 'Credential theft' in threatmodel 'Payments' (models/payments.hcl): Every threat must have at least one implemented control
Checked 3 invariants against 4 threatmodels: 1 errors, 0 warnings, 1 exemptions
```

Each violation names the offending item, its threat model, and the file it came
from, so the output is actionable without opening anything. Exemptions are
printed with their justification — a waiver stays visible in every run rather
than quietly suppressing a finding.

The exit code is non-zero if:

- the threat models themselves fail validation,
- the invariants file is invalid,
- an invariant expression fails to evaluate (that's a bug in the rule, and it's
  reported loudly rather than skipped), or
- any `error`-severity invariant is violated.

`warning`-severity violations are reported but exit zero.

## Rolling out a new rule

The two severities make invariants easy to adopt in CI without a flag day:

1. Add the rule with `severity = "warning"`. CI keeps passing, and every run
   prints the models that don't comply.
2. Fix the fleet — or add an `exemption` block with a justification for the
   models that are genuinely allowed to differ.
3. Flip the rule to `severity = "error"` (the default) once the warnings are
   gone. From then on, a regression fails the build.

Exemptions live in the invariants file, not in the threat model, so a model
can't waive a rule for itself.

## Invariants in Threatcl Cloud

Threatcl Cloud's policy engine speaks invariants too, so the same file can gate
a pull request locally and every model in your organization centrally. A cloud
policy is either a Rego module (engine `rego`) or a single `invariant` block
(engine `invariant`); the cloud runs the same evaluator this page describes, so
a rule's verdict doesn't change when it moves.

Push a whole invariants file with `sync-invariants`. Each `invariant` block
becomes one policy, addressed by its name label, so re-running it after an edit
updates the same policies rather than piling up new ones:

```bash
threatcl cloud policy sync-invariants invariants.hcl
```

```
Parsed 3 invariants from invariants.hcl

  + no_public_unauth (created)
  ~ threats_have_controls (updated)

1 created | 1 updated
```

The import is all-or-nothing — if any block fails, nothing is imported — and
the cloud-side settings you manage in the UI (enabled, enforced, category,
tags) survive a re-run. Individual blocks can also be managed one at a time:

```bash
threatcl cloud policy validate -engine=invariant invariants.hcl
threatcl cloud policy create -engine=invariant -file=one-invariant.hcl
threatcl cloud policy update -policy-id=<uuid> -engine=invariant -file=one-invariant.hcl
threatcl cloud policies -engine=invariant
```

`create` takes the policy's name and severity from the block, so there's one
place to change them. Severity means the same thing it does locally, and there
is no `info` level for invariants.

Evaluating a model reports violations the way `validate` does, naming the item,
its segment, and the rendered message:

```bash
threatcl cloud policy evaluate -model-id=<uuid> -fail-on-error
```

Two differences are worth knowing before you push a file up:

- **Exemptions resolve against HCL identities, not cloud display names.** A
  model shown as "Payments Service" in the cloud whose file declares
  `threatmodel "Payments"` is exempted as `threatmodel["Payments"]`, or by its
  dotted `id`. Accepting the display name would validate a waiver that never
  fires. Exemptions are also segment-granular: exempting a root segment leaves
  its children checked.
- **Validation is organization-scoped.** The cloud resolves every exemption
  against the models your org has, so `cloud policy validate` can reject a file
  that parses cleanly on your laptop.

Not every deployment offers the invariant engine. When it's off, these commands
report that the feature isn't enabled and evaluation ignores invariant
policies; run `threatcl validate -invariants` locally in the meantime.
