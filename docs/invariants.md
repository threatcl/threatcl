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
