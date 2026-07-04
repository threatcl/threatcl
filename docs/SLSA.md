# SLSA posture — threatcl CLI

This document tracks the [SLSA](https://slsa.dev) supply-chain posture of the
`threatcl` CLI (`github.com/threatcl/threatcl`). Unlike the upstream
[`threatcl/spec`](https://github.com/threatcl/spec) library — which only ships a
source archive — this repo **compiles and ships binaries and container images to
end users**, so the Build track is genuinely meaningful here: there are real
artifacts to attest.

It maps every planned change to a specific SLSA **track + level**, and stays
honest about what is and isn't *formally* met (notably: GitHub does not yet emit
Source VSAs, so Source-track levels can only be claimed "in substance").

References:
- Build track (v1.1): <https://slsa.dev/spec/v1.1/levels>
- Source track (v1.2, 4 levels): <https://slsa.dev/spec/v1.2/source-requirements>

Status legend: ✅ done · 🔶 partial / in substance · ⛔ not met · ➖ out of scope

---

## TL;DR — current vs target

| Track  | Current (2026-06-28)            | Target (this effort)                                   |
|--------|---------------------------------|--------------------------------------------------------|
| Build  | **L2, in substance L3** — signed SLSA provenance wired for every artifact + image-by-digest (Phase 3); emitted on each `v*` release | **reached** — GitHub-hosted isolated builds, keyless-signed provenance, consumer-verifiable |
| Source | **L3 controls in force** (in substance; no VSA) — non-bypassable `main` + `v*` rulesets active | **reached** — L3-shaped controls enforced (no VSA, GitHub limitation), L4 ➖ (solo maintainer) |

The headline **Build L0 → L2/L3** gap is now closed: Phase 3 wired
[`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance)
into the release job, so every tagged release emits Sigstore-signed SLSA
provenance over each platform archive, the `SHA256SUMS` file, and the multi-arch
container image (by digest). **Source track Phase 2** is now done too: the
importable branch/tag rulesets under `.github/rulesets/` plus `.github/CODEOWNERS`
ship in the repo **and** have been imported — both rulesets are **active and
non-bypassable** on `main` + `v*` (PR + `testvet`/`validate` + signed + linear +
squash; immutable signed tags). See the
[activation record](#phase-2-active--source-l3-controls-in-substance). The
now-redundant legacy classic branch protection on `main` has been removed, leaving
the ruleset as the single source of truth.

---

## Build track

### Current state — Build L0

The release pipeline (`.github/workflows/threatcl-release.yml`, tag-triggered on
`v*`) does plain matrix `go build`:

- Binaries: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`,
  `windows/amd64` (`CGO_ENABLED=0`).
- Packaged as `.tar.gz` / `.zip` with a `BUILD_TIME` timestamp in the filename,
  uploaded to a GitHub Release via `softprops/action-gh-release`.
- A separate job builds and pushes a multi-arch Docker image
  (`linux/amd64,linux/arm64`) to `ghcr.io/threatcl/threatcl`, tagged `latest` +
  version.

| Build requirement                                  | Status | Notes                                                        |
|----------------------------------------------------|--------|--------------------------------------------------------------|
| L1 — provenance exists (may be unsigned/incomplete)| ✅ (Phase 3) | Signed SLSA provenance is generated for every archive, `SHA256SUMS`, and the image. |
| L1 — consistent, scripted build process            | ✅     | Builds are fully scripted in the workflow.                   |
| L2 — build runs on a hosted platform               | ✅     | GitHub-hosted `ubuntu-latest` runner — now meaningful because provenance is attested. |
| L2 — provenance generated **and signed** by platform| ✅ (Phase 3) | `actions/attest-build-provenance` — keyless GitHub OIDC → Fulcio, signed by the platform. |
| L2 — consumer can validate provenance authenticity | ✅ (Phase 3) | `gh attestation verify` for both binaries and the image-by-digest (documented in README). |
| L3 — isolated, hardened builds; signing secrets not reachable by build steps | 🔶 (in substance) | GitHub-hosted ephemeral runner + OIDC→Fulcio keyless signing — no user-controlled signing key is exposed to any build step. No third-party audit, so claimed in substance only. |
| Checksums file (SHA256SUMS) published              | ✅ (Phase 2.5) | GoReleaser emits `SHA256SUMS` over every archive; Phase 3 also attests it. |

**Honest read:** the release job now generates platform-signed, consumer-verifiable
provenance for every artifact, so this reaches **Build L2** formally, with the L3
isolation/hardening properties met **in substance** (ephemeral hosted runners +
keyless signing). Provenance is emitted from the next `v*` tag onward.

### Phase 2.5 (done) — GoReleaser migration

Before wiring provenance, the release pipeline was rebuilt around
[GoReleaser](https://goreleaser.com) (replacing two ~95%-duplicated hand-rolled
workflows). This is groundwork for Build provenance, not a level change on its
own — it stays **Build L0** until Phase 3 adds attestations. What it buys:

- **Deterministic, stable artifact names** (`threatcl_<version>_<os>_<arch>.tar.gz`,
  windows `.zip`) — the old `BUILD_TIME`-stamped names were hostile to
  verification. `-trimpath` reproducible builds.
- **`SHA256SUMS`** over all archives (download-integrity).
- **Version stamped from the git tag** via `-ldflags -X …/version.Version` (no
  more manual `version.go` bumps).
- **Single build path for the container image** (Option B): the image `COPY`s the
  *same* binary that's in the archive (`Dockerfile.goreleaser` is COPY-only), so
  the bytes a user verifies in the archive are the bytes in the image. Multi-arch
  via `dockers_v2`; an **SBOM is attached to the image** by default.
- **One ubuntu runner** cross-compiles all 5 targets (dropped the macOS/Windows
  runners — pure-Go `CGO_ENABLED=0`).
- **Security-aware triggers**: PR = build-only dry-run (fork-safe, read-only);
  push-to-main = rolling `dev` pre-release; tag `v*` = full release. Images are
  pushed **only** on tags (`:v<version>` + `:latest`).

### Phase 3 (done) — Build L2, in substance L3

Phase 3 wired [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance)
(v4.1.1, SHA-pinned) into the `release` job of the GoReleaser pipeline:

- Sigstore-signed SLSA provenance (keyless, GitHub OIDC → Fulcio) for **every
  released artifact**: one attestation over each platform archive + the
  `SHA256SUMS` file (`subject-path` glob over `dist/`).
- Docker image provenance attested **by digest**, pushed to ghcr.io as an OCI
  referrer. The pushed multi-arch manifest digest is resolved with
  `docker buildx imagetools inspect … --format '{{ .Manifest.Digest }}'`, so the
  attested digest covers both `:v<version>` and `:latest` (same push).
- `id-token: write` + `attestations: write` scoped to the `release` job only —
  the PR `validate` and push-to-main `dev` jobs never get signing privileges.
- `gh attestation verify` documented in the README for both binaries and the
  image-by-digest.

This reaches **Build L2** formally (provenance generated + signed by the
platform, consumer-verifiable). The **L3** isolation/hardening properties are met
*in substance* by GitHub-hosted ephemeral runners + keyless OIDC signing (no
signing secret is ever exposed to build steps), the same posture accepted in
`threatcl/spec`. We do not claim formal L3 certification — there is no third-party
audit of the build platform — but the technical controls are L3-shaped.

---

## Source track (v1.2 — 4 levels)

### Current state

Live state as of 2026-06-28 (`gh api`) — **Phase 2 activated**, both rulesets
imported and enforcing:

- **Two active rulesets** (`repos/threatcl/threatcl/rulesets`):
  - `main branch protection` (branch, `~DEFAULT_BRANCH`, enforcement **active**):
    require PR (**0 approvals**), require status checks **`testvet` + `validate`**
    (strict), `required_signatures`, `required_linear_history`, squash-only
    (`allowed_merge_methods: ["squash"]`), `non_fast_forward` (no force-push), and
    `deletion` blocked. **`bypass_actors: []`** — non-bypassable, including for the
    admin/maintainer.
  - `release tag protection` (tag, `refs/tags/v*`, enforcement **active**):
    `deletion` + `update` + `non_fast_forward` blocked, `required_signatures`.
    `bypass_actors: []`. (The floating `latest` and rolling `dev` tags are
    deliberately out of scope.)
- **Legacy classic branch protection — removed.** The old classic protection on
  `main` (1-approval PR, `enforce_admins: false`, no signatures, no status checks)
  was fully superseded by the ruleset and deleted on 2026-06-28
  (`gh api -X DELETE repos/threatcl/threatcl/branches/main/protection` → 404).
  Its only unique rule — a 1-approval requirement — conflicted with the
  solo-maintainer 0-approval design and was the source of the #169 "1 approving
  review required" merge block. The ruleset is now the single source of truth
  for `main`.
- **CODEOWNERS** present (`.github/CODEOWNERS`, default owner `@xntrik`).
- **Signing enforced**: commit + tag signing is configured locally (SSH signing
  via Secretive / Secure Enclave); `required_signatures` now enforces it on both
  `main` and `v*` tags. Recent `v*` tags are annotated, signed tag objects.

| Source requirement                                                   | Level | Status | Notes |
|----------------------------------------------------------------------|-------|--------|-------|
| Version controlled, stable repo + revision locators, diff tooling    | L1    | 🔶     | GitHub provides all of this; but no **Source VSA** is emitted (GitHub limitation). "L1 in substance." |
| Immutable history — no force-push to `main`                          | L2    | ✅     | Ruleset `non_fast_forward` + `deletion` on `main` (and `v*` tags); non-bypassable. |
| Change attribution (who/when/new revision id)                        | L2    | ✅     | Native git + GitHub history. |
| Contemporaneous **Source Provenance** attestations                   | L2    | ⛔     | GitHub does not produce these. |
| Continuous **enforced** technical controls, recorded in attestations | L3    | 🔶     | Non-bypassable rulesets are **active** on `main` + `v*` (`bypass_actors: []`): PR + `testvet`/`validate` + signatures + linear history. Controls are now *in force* — but still no Source Provenance/VSA attestations (GitHub limitation), so "L3 in substance," not platform-attested. |
| Two-party review of every change to protected branches               | L4    | ➖     | Solo maintainer — not achievable without a second trusted reviewer. |

**Honest read:** **Source L1 in substance** (no VSA), now with the **L3-shaped
technical controls active and non-bypassable** — Phase 2's rulesets are imported
and enforcing on `main` + `v*` (PR + CI + signature + linear-history + tag
immutability, `bypass_actors: []`, no admin escape hatch). The remaining gap is
the one GitHub can't close yet: no Source Provenance/VSA attestation, so this is
"L2/L3 controls in force," not platform-attested. **L4** is still gated on a
second reviewer.

### Phase 2 (active) — Source L3 controls, in substance

Phase 2 ports the `threatcl/spec` patterns. It ships three **committed**
artifacts (version-controlled templates GitHub never auto-reads) that were then
imported and activated (see the record below):

- `.github/CODEOWNERS` — default owner `@xntrik`, so the maintainer is the
  default reviewer (and the routing is already in place the day a second
  reviewer is added).
- `.github/rulesets/main-protection.json` — importable branch ruleset for `main`:
  require PR, require **both** status checks (`testvet` + `validate`), block
  force-push, restrict deletion, require linear history, squash-only, and
  **required signed commits**.
- `.github/rulesets/tag-protection.json` — importable tag ruleset for `v*` tags:
  immutable (no delete / no update / no force) + **signed**.

**Two required status checks (threatcl-specific).** Unlike `threatcl/spec` (which
gates on `testvet` alone), this repo *compiles and ships binaries and images*, so
the merge gate also requires `validate` — the GoReleaser cross-platform
build/packaging/Dockerfile dry-run from `release.yml`. Both run on every PR to
`main` (`validate` is `if: pull_request`, fork-safe and read-only), so neither
deadlocks the gate. The effect: nothing reaches `main` unless it still **builds
for all five targets + the image**, which directly protects the Build track's
inputs.

**Solo-maintainer trade-off (deliberate).** The branch ruleset sets
`required_approving_review_count: 0` and `bypass_actors: []`. This still forces
**every** change through a PR and still enforces CI + signatures + no-force-push +
linear history *on the maintainer* — it just drops an approval a solo maintainer
can't give themselves. A bypass actor is deliberately **not** added: a bypass
skips the *entire* ruleset (CI gate, signature requirement, force-push protection
— not just review), which would defeat the point. When a second reviewer joins,
bump the count to `1` and set `require_code_owner_review: true` for true Source L4
two-party review; `CODEOWNERS` is already wired to route it.

Activating both rulesets enforces the **L3-shaped technical controls**
(continuous, non-bypassable, applied to protected refs). We still **cannot
formally claim Source L2/L3** because GitHub emits **no Source Provenance / VSA**
attestations — the spec requires those produced contemporaneously and they simply
don't exist yet on GitHub. We are honest about this gap. **L4 (two-party review)
is out of scope** for a single maintainer.

#### Maintainer activation record — GitHub settings

> **✅ Activated 2026-06-28.** Both rulesets were imported and are enforcing on
> `main` + `v*`, and the redundant legacy classic branch protection was removed.
> The steps below are kept as the activation/repro record.

The rulesets are **not auto-applied** — GitHub never reads these files. They are
version-controlled templates imported by hand (UI) or pushed with `gh api`, in
this order.

**Step 1 — Signing (already configured).** Both rulesets require signatures.
Commit + tag signing is already set up locally via SSH signing (Secretive /
Secure Enclave). Confirm with `git log --show-signature` / `git tag -v vX.Y.Z`.

- [x] SSH signing configured locally and signing key added to GitHub as a
  **Signing Key**.

> **Sign *before* you open PRs.** The signature rule is enforced at the PR merge
> gate: GitHub blocks the merge while **any commit in the PR is unverified**, even
> for squash merges. If a branch has unsigned commits, re-sign and force-push
> before merging (`git rebase -f -S main && git push --force-with-lease`).
> **Tags** are created and pushed locally, so `git tag -s` is mandatory once the
> tag ruleset is active (see `CONTRIBUTING.md`).
>
> *Agent-backed keys (Secretive / Secure Enclave):* set `user.signingkey` to the
> literal key (`key::ssh-ed25519 AAAA…`), and ensure `SSH_AUTH_SOCK` points at
> that agent — git's signer finds the agent via `SSH_AUTH_SOCK`, not via
> `IdentityAgent` in `ssh_config`.

**Step 2 — Import the `main` branch ruleset.** Settings → Rules → Rulesets →
**New ruleset → Import a ruleset** → select `.github/rulesets/main-protection.json`.
Or via the API:

```bash
gh api repos/threatcl/threatcl/rulesets \
  --method POST --input .github/rulesets/main-protection.json
```

It encodes:

- [x] Require a pull request before merging (**0 approvals** — solo default).
- [x] Require status checks **`testvet`** *and* **`validate`** (strict /
  up-to-date).
- [x] **Block force-pushes** (`non_fast_forward`) — Source L2 move-forward-only.
- [x] **Restrict deletions** of `main`.
- [x] **Require linear history** + **squash-only** merges (no more merge commits;
  PRs land as a single squashed, GitHub-signed commit).
- [x] **Require signed commits** (`required_signatures`).

> Want CodeQL gated on merge too? Add `{ "context": "Analyze (go)" }` (the
> `codeql.yml` check name) to `required_status_checks` and re-import. Left out of
> the shipped default to avoid merge friction from the slower scan.

**Step 3 — Import the tag ruleset.** Same flow with
`.github/rulesets/tag-protection.json` (or `gh api … /rulesets --method POST
--input …`). It makes `v*` tags **immutable + signed**:

- [x] Block tag **deletion**, **update**, and **force** (`deletion`, `update`,
  `non_fast_forward`) — Source L2 tag immutability.
- [x] **Require signed tags** (`required_signatures`). Applies to new tags only;
  existing unsigned tags are unaffected. Don't activate before Step 1 or your next
  `git push --tags` is rejected.

> **Scope is `refs/tags/v*` only — by design.** The floating `latest` tag
> (`git tag -f latest`) and the rolling `dev` pre-release tag are **not** covered,
> so the release flow's force-moved/unsigned non-version tags keep working. Only
> the immutable `vX.Y.Z` release points are locked down.

**What this advanced.** With both rulesets active, the **Source track** moved from
"L1 in substance" to the **L2/L3 technical-control** posture: continuous, enforced
controls on `main` and on release tags — immutable history, blocked force-push,
required signatures, two required CI gates. The formal **Source VSA** an SCS is
expected to emit still doesn't exist (GitHub limitation), so this is "L2/L3
controls in force," not a platform-attested L2/L3. **Source L4** remains gated on
a second reviewer.

---

## Supply-chain hygiene (cross-cutting)

These underpin both tracks (a compromised Action can forge provenance or push to
`main`).

| Control                                              | Status | Notes |
|------------------------------------------------------|--------|-------|
| All Actions SHA-pinned with `# vX.Y.Z` comment       | ✅ (Phase 1) | Every `uses:` across all workflows pinned to a full commit SHA + version comment. The lone `@latest` left is inside a commented-out dead block. |
| Dependabot (github-actions + gomod)                  | ✅ (Phase 1) | `.github/dependabot.yml` covers `github-actions`, `gomod`, and `docker` (base images), weekly, grouped. Will drive the older `docker/*` action pins up to current majors as CI-gated PRs. |
| Least-privilege top-level `permissions: contents: read` | ✅ (Phase 1) | All workflows declare top-level `contents: read`; jobs that upload SARIF add `security-events: write` only. |
| Job-scoped escalation only where needed              | ✅ (Phase 1) | Build-only jobs dropped to inherit `contents: read` (they only `upload-artifact`). Escalation kept only on jobs that need it: `release`/`pre-release` (`contents: write`, GitHub Release), image push (`packages: write`). `pre-build-image-test` dropped `packages: write` (it's `push: false`). |
| CodeQL scanning                                      | ✅ (Phase 5: `security-extended`) | `.github/workflows/codeql.yml` runs on push/PR to `main` + weekly, with the `security-extended` query suite. Chosen **instead of** a second Go SAST (gosec): CodeQL's Go queries cover most gosec rules with interprocedural dataflow and fewer false positives; two SASTs would double triage noise. |
| govulncheck (known-vuln Go deps, reachability-aware) | ✅ (Phase 5) | `.github/workflows/govulncheck.yml` on push/PR + weekly. Binary pinned; the vuln DB is fetched live so freshness doesn't depend on the pin. |
| Dependency review gate on PRs                        | ✅ (Phase 5) | `.github/workflows/dependency-review.yml` fails PRs that *introduce* deps with known vulns (`fail-on-severity: low`). |
| zizmor (workflow static analysis)                    | ✅ (Phase 5) | `.github/workflows/zizmor.yml`, SARIF → code scanning. Baseline findings fixed: `persist-credentials: false` on every checkout; `cache: false` on `setup-go` in the artifact-building `release.yml` jobs (cache-poisoning). |
| Trivy scan of the **published** image                | ✅ (Phase 5) | `.github/workflows/trivy.yml`, weekly + manual, scans `ghcr.io/threatcl/threatcl:latest` for newly disclosed base-layer (alpine) CVEs post-publication; SARIF → code scanning. Token-free replacement for the old Snyk container scan. |
| harden-runner egress monitoring                      | 🔶 (Phase 5) | `step-security/harden-runner` on every job, `egress-policy: audit`. Follow-up: flip the `release` job (and then the rest) to `block` + `allowed-endpoints` once audit baselines exist. |
| GoReleaser pinned to an exact version                | ✅ (Phase 5) | `goreleaser-action` previously floated `"~> v2"` — the binary is downloaded at run time, so the range was an unpinned build tool inside the most privileged job. Now `v2.16.0`, bumped deliberately. |
| Base images digest-pinned                            | ✅ (Phase 5) | `Dockerfile` + `Dockerfile.goreleaser` pin `alpine`/`golang` bases by manifest-list digest; Dependabot's docker ecosystem updates digests alongside tags. |
| SBOMs for released archives (SPDX, syft)             | ✅ (Phase 5) | `.goreleaser.yaml` `sboms:` emits one SBOM per archive; uploaded to releases (incl. the rolling `dev` pre-release) and covered by the release attestation step. The image already had an SBOM via `dockers_v2`. |

> **Carry-over resolved in Phase 2.5:** the old `docker/*` pins (`login-action`
> v1.10.0, `metadata-action` v3.3.0, `build-push-action` v2.5.0) and the
> `mknejp/delete-release-assets@v1` branch pin lived in the two release workflows
> that the GoReleaser migration **deleted**. The new `release.yml` uses current
> `docker/login-action` v4.2.0, `setup-qemu`/`setup-buildx` v4.1.0, and
> `goreleaser-action` v7.2.2 — all SHA-pinned with version comments.

---

## Progress tracker

| Phase | Change                                                                 | Advances                         | Status |
|-------|------------------------------------------------------------------------|----------------------------------|--------|
| 0     | Recon + this `docs/SLSA.md`                                             | (baseline)                       | ✅ |
| 1     | SHA-pin all Actions w/ `# vX.Y.Z`                                       | Hygiene (protects both tracks)   | ✅ |
| 1     | Add `dependabot.yml` (github-actions + gomod + docker)                 | Hygiene                          | ✅ |
| 1     | Least-privilege `permissions:` on every workflow (fix `testvet.yml`)   | Hygiene                          | ✅ |
| 2.5   | Migrate release pipeline to GoReleaser (`.goreleaser.yaml`, consolidated `release.yml`) | Build groundwork (determinism, single build path) | ✅ |
| 2.5   | Deterministic artifact names + version ldflags injection               | Build groundwork                 | ✅ |
| 2.5   | Multi-arch image via `dockers_v2`, image binary == archive binary + SBOM | Build groundwork (images)        | ✅ |
| 2     | Branch ruleset on `main` (PR + `testvet`/`validate` checks + signed + linear + squash)| Source L2→L3 controls (in substance) | ✅ active¹ |
| 2     | Tag ruleset on `v*` (immutable + signed)                               | Source L2/L3 (tag immutability)  | ✅ active¹ |
| 2     | `CODEOWNERS`                                                           | Source (review routing)          | ✅ |
| 2     | Non-bypassable enforcement (empty bypass list; no admin escape hatch)  | Source L3 (enforcement)          | ✅ active¹ |
| 3     | `SHA256SUMS` checksums file in releases                                | Build (integrity)                | ✅ (done in 2.5) |
| 3     | `attest-build-provenance` on every binary + checksums                  | **Build L0→L2 (in substance L3)**| ✅ |
| 3     | Attest Docker image **by digest**                                      | Build L2 (images)                | ✅ |
| 3     | README `gh attestation verify` docs (binaries + images-by-digest)      | Build L2 (consumer validation)   | ✅ |
| 5     | Vuln scanning: `govulncheck` (push/PR + weekly) + PR dependency-review + weekly Trivy of the published image | Hygiene (vuln detection at source + post-publish) | ✅ |
| 5     | zizmor workflow static analysis + baseline fixes (`persist-credentials: false` everywhere, no Go build cache in `release.yml`) | Hygiene (workflow control plane) | ✅ |
| 5     | harden-runner on every job (`egress-policy: audit`)                     | Hygiene / Build isolation        | 🔶 audit; block pending baselines |
| 5     | Exact GoReleaser version pin + digest-pinned base images                | Build (pinned toolchain + inputs)| ✅ |
| 5     | SBOMs for released archives (syft, SPDX) — uploaded + attested          | Build (transparency)             | ✅ |
| 5     | CodeQL `security-extended` suite (chosen over adding gosec)             | Hygiene (SAST depth)             | ✅ |

> ¹ **Activated 2026-06-28.** Both rulesets were imported from the committed JSON
> and are live + non-bypassable on `main`/`v*` (`bypass_actors: []`); the redundant
> legacy classic branch protection on `main` was removed the same day. See the
> [activation record](#maintainer-activation-record--github-settings).

---

## Honest limitations (what we are *not* claiming)

- **No Source VSA.** GitHub does not emit Source Verification Summary Attestations
  or Source Provenance documents. Source-track levels above L1 require these, so
  we claim the L2/L3 **technical controls "in substance"** only — not formal
  certification.
- **No formal Build L3 audit.** We rely on GitHub-hosted ephemeral runners +
  keyless OIDC signing for isolation. The technical controls are L3-shaped, but
  there is no third-party attestation of the build platform itself.
- **Source L4 is out of scope.** Two-party review is not achievable with a single
  maintainer; we explicitly choose require-PR-with-0-approvals instead of a fake
  approval or an admin bypass.
- **Build provenance generator choice.** We use first-party GitHub attestations
  (`actions/attest-build-provenance`) rather than `slsa-framework/slsa-github-generator`.
  Rationale is recorded in Phase 3; the short version is a clean, first-party
  `gh attestation verify` UX with native multi-artifact + by-digest image support.

---

## Verification (for end users)

Every `v*` release carries Sigstore-signed SLSA build provenance. Verify with the
[GitHub CLI](https://cli.github.com) — no keys or extra tooling required (this is
also documented in the README).

**Binaries / archives** — verify a downloaded archive (or the `SHA256SUMS` file):

```bash
gh attestation verify threatcl_<version>_<os>_<arch>.tar.gz --repo threatcl/threatcl
```

**Container image** — verify by tag (resolved to its digest automatically):

```bash
gh attestation verify oci://ghcr.io/threatcl/threatcl:<version> --repo threatcl/threatcl
```

Or pin to an immutable digest and verify that exact image:

```bash
digest=$(docker buildx imagetools inspect ghcr.io/threatcl/threatcl:<version> --format '{{ .Manifest.Digest }}')
gh attestation verify oci://ghcr.io/threatcl/threatcl@${digest} --repo threatcl/threatcl
```

A successful verify confirms the artifact was built by this repo's `release`
workflow from a `v*` tag, on a GitHub-hosted runner, signed keylessly via GitHub
OIDC → Fulcio.
