# Invariants

Invariants are org-wide, machine-checked rules evaluated against your threat
models — things like "no public endpoints should be unauthenticated" or "all
internet-facing features must document audit logging". They live in their own
HCL file, separate from your threat models, so one rule set can govern an
entire fleet of models.

```bash
threatcl validate -invariants=invariants.hcl ./models/
```

`threatcl validate` first validates the threat model files as usual, then
evaluates every invariant against every validated model. Violations of
severity `error` make validation fail (non-zero exit); `warning` violations
are reported but don't fail the run. This makes invariants easy to enforce in
CI: introduce a new rule as a `warning`, fix the fleet, then flip it to
`error`.

## The invariants file

An invariants file contains one or more `invariant` blocks:

```hcl
invariant "no_unauthenticated_public_endpoints" {
  description = "No public endpoints should be unauthenticated"
  severity    = "error"
  target      = "process"
  when        = item.trust_zone == "Public"
  condition   = anytrue([for c in tm.controls : c.implemented && can(regex("(?i)auth", c.name))])
}

invariant "internet_facing_models_document_audit_logging" {
  description = "All internet-facing features must emit audit logs"
  severity    = "warning"
  target      = "threatmodel"
  when        = item.attributes.internet_facing
  condition   = anytrue([for c in tm.controls : can(regex("(?i)audit", c.name))])

  error_message = "threatmodel '${item.name}' is internet-facing but documents no audit logging control"

  exemption {
    model         = threatmodel["Legacy Public API"]
    justification = "Grandfathered until Q3 migration; tracked in SEC-123"
  }
}

invariant "threats_have_implemented_controls" {
  description = "Every threat must have at least one implemented control"
  target      = "threat"
  condition   = anytrue([for c in item.controls : c.implemented])
}
```

### Attributes

| Attribute       | Required | Meaning                                                                                                     |
| --------------- | -------- | ----------------------------------------------------------------------------------------------------------- |
| `target`        | yes      | Which collection the rule applies to (see [Targets](#targets)). The condition runs once per item.            |
| `condition`     | yes      | HCL expression that must evaluate to `true` for each targeted item. `false` records a violation.             |
| `when`          | no       | HCL expression filtering which items the rule applies to. Items where `when` is `false` are skipped.         |
| `severity`      | no       | `"error"` (default) or `"warning"`. Only error violations fail validation.                                   |
| `description`   | no       | Human explanation; used as the violation message when `error_message` isn't set.                             |
| `error_message` | no       | HCL string expression for the violation message. May interpolate `item`, `tm`, and (for DFD targets) `dfd`.  |

### Exemptions

An `exemption` block waives the invariant for one threat model, with a
required justification so the waiver is auditable:

```hcl
exemption {
  model         = threatmodel["Legacy Public API"]
  justification = "Why this model is allowed to violate the rule"
}
```

`model` is a real reference, not a string: `threatmodel` is a registry of the
models in the current validate run, keyed by name. Referencing a model that
isn't in the run is a hard error that lists the models that are — so a typo'd
or renamed model can't leave a silently-dead waiver behind. Because the
reference resolves to the actual model object, field access works too
(`threatmodel["Legacy Public API"].author`), though an exemption's `model`
must be the model itself, not a field of it.

If one invariants file is shared across fleets that are validated separately,
wrap the reference so it's inactive where the model isn't present:

```hcl
model = try(threatmodel["Other Fleet's Model"], null)
```

Exemptions live in the invariants file — not in the threat model — so models
can't waive rules for themselves. Exempted models are skipped (not evaluated)
and reported with their justification.

## Targets

The `target` attribute picks the collection each item comes from. The
condition is evaluated once per item, so violations name the exact offending
item.

| Target                   | Item                                                                                    |
| ------------------------ | --------------------------------------------------------------------------------------- |
| `threatmodel`            | The threat model itself (one item per model)                                             |
| `threat`                 | Each `threat` block                                                                      |
| `control`                | Each control across all threats (inline `control` blocks plus imported controls)         |
| `information_asset`      | Each `information_asset` block                                                           |
| `usecase`                | Each `usecase` block                                                                     |
| `exclusion`              | Each `exclusion` block                                                                   |
| `third_party_dependency` | Each `third_party_dependency` block                                                      |
| `data_flow_diagram`      | Each `data_flow_diagram_v2` block (legacy `data_flow_diagram` blocks are included too)   |
| `process`                | Each DFD process, including those nested in `trust_zone` blocks                          |
| `external_element`       | Each DFD external element, including nested                                              |
| `data_store`             | Each DFD data store, including nested                                                    |
| `flow`                   | Each DFD flow                                                                            |
| `trust_zone`             | Each DFD trust zone                                                                      |

## Expressions

`when`, `condition`, and `error_message` are native HCL expressions. Three
variables are in scope:

- `item` — the current target item.
- `tm` — the threat model that owns the item (for `target = "threatmodel"`,
  `item` and `tm` are the same object).
- `dfd` — the owning diagram, only for the DFD element targets (`process`,
  `external_element`, `data_store`, `flow`, `trust_zone`).

### The `tm` object

| Field                      | Type           | Notes                                                              |
| -------------------------- | -------------- | ------------------------------------------------------------------ |
| `name`, `description`, `author`, `link`, `diagram_link` | string | |
| `repository`               | list(string)   |                                                                    |
| `created_at`, `updated_at` | number         | Unix timestamps                                                    |
| `attributes`               | object         | `new_initiative` (bool), `internet_facing` (bool), `initiative_size` (string); all-defaults when the block is absent |
| `additional_attributes`    | map(string)    | `additional_attribute` blocks as a name → value map                |
| `information_assets`       | list(object)   | `name`, `description`, `information_classification`, `source`, `ref` |
| `threats`                  | list(object)   | See below                                                          |
| `usecases`, `exclusions`   | list(object)   | Each has `description`                                             |
| `third_party_dependencies` | list(object)   | `name`, `description`, `saas`, `paying_customer`, `open_source`, `uptime_dependency`, `uptime_notes`, `infrastructure` |
| `data_flow_diagrams`       | list(object)   | See below                                                          |
| `controls`                 | list(object)   | Convenience: every control across every threat, flattened          |

Each threat has `name`, `description`, `impacts`, `stride`,
`information_asset_refs`, `control` (the legacy string attribute), `ref`,
`controls`, `proposed_controls`, and `risk` (an object with `likelihood`,
`impact`, `severity`, `rationale` — or `null` when the threat has no risk
block). Each control has `name`, `implemented`, `description`,
`implementation_notes`, `ref`, `risk_reduction`, and `attributes` (a
name → value map of its `attribute` blocks).

Each data flow diagram has `name`, `processes`, `external_elements`,
`data_stores`, `flows`, and `trust_zones`. The element lists include elements
nested inside `trust_zone` blocks, and every element's `trust_zone` field is
resolved (nested elements report the enclosing zone). Flows have `name`,
`from`, `to`, `protocol`.

Every string field is present (empty rather than null), so comparisons like
`item.protocol != ""` are safe without null checks.

### Functions

The usual expression toolkit is available: `alltrue`, `anytrue`, `can`, `try`,
`coalesce`, `compact`, `concat`, `contains`, `distinct`, `element`, `flatten`,
`format`, `join`, `keys`, `length`, `lookup`, `lower`, `max`, `merge`, `min`,
`regex`, `regexall`, `replace`, `reverse`, `sort`, `split`, `substr`, `trim`,
`trimprefix`, `trimspace`, `trimsuffix`, `upper`, `values`, `zipmap`. These
behave like their Terraform counterparts.

Quantification uses `for` expressions:

```hcl
# every: all controls implemented
condition = alltrue([for c in item.controls : c.implemented])

# exists: at least one confidential asset
condition = anytrue([for a in tm.information_assets : a.information_classification == "Confidential"])

# none: no flow uses plain http
condition = length([for f in item.flows : f if lower(f.protocol) == "http"]) == 0
```

## Output and exit codes

```
$ threatcl validate -invariants=invariants.hcl ./models/
Validated 4 threatmodels in 3 files
Invariant 'internet_facing_models_document_audit_logging' exempts threatmodel 'Legacy Public API' (models/legacy.hcl): Grandfathered until Q3 migration; tracked in SEC-123
Invariant violation [error] 'threats_have_implemented_controls': threat 'Credential theft' in threatmodel 'Payments' (models/payments.hcl): Every threat must have at least one implemented control
Checked 3 invariants against 4 threatmodels: 1 errors, 0 warnings, 1 exemptions
```

The exit code is non-zero if the threat models themselves fail validation, if
the invariants file is invalid, if an invariant expression fails to evaluate
(that's a bug in the rule, and it's reported loudly rather than skipped), or
if any error-severity invariant is violated. Warnings alone exit zero.

`-invariants` also works with `-stdin`/`-stdinjson`; violations are attributed
to `STDIN`.
