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

| Track  | Current (2026-06-27)            | Target (this effort)                                   |
|--------|---------------------------------|--------------------------------------------------------|
| Build  | **L0** — no provenance at all   | **L2, in substance L3** — signed SLSA provenance on every artifact, GitHub-hosted isolated builds |
| Source | **L1 in substance** (no VSA), a few L2 controls present-but-not-enforced | **L3 controls enforced** (in substance; no VSA), L4 ➖ (solo maintainer) |

The headline gap is **Build L0 → L2/L3**: the release pipeline builds 5 platform
binaries and multi-arch Docker images but produces **zero** provenance and **no
checksums file**. Phase 3 is the main event.

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
| L1 — provenance exists (may be unsigned/incomplete)| ⛔     | No provenance is generated for binaries or images.           |
| L1 — consistent, scripted build process            | ✅     | Builds are fully scripted in the workflow.                   |
| L2 — build runs on a hosted platform               | ✅ (latent) | GitHub-hosted `ubuntu/macos/windows-latest` runners — but worthless for SLSA until provenance exists. |
| L2 — provenance generated **and signed** by platform| ⛔    | None.                                                        |
| L2 — consumer can validate provenance authenticity | ⛔     | Nothing to validate; no `gh attestation verify` story.       |
| L3 — isolated, hardened builds; signing secrets not reachable by build steps | 🔶 (latent) | GitHub-hosted ephemeral runners + OIDC→Fulcio keyless signing provide this *once attestation is wired*; no user-controlled signing key is exposed to build steps. |
| Checksums file (SHA256SUMS) published              | ✅ (Phase 2.5) | GoReleaser now emits `SHA256SUMS` over every archive on release. Integrity ✓; provenance still pending (Phase 3). |

**Honest read:** despite running on hosted, isolated runners (which would
*support* L2/L3), the absence of any generated provenance pins this at **Build
L0** today.

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

### Target state — Build L2, in substance L3

Phase 3 wires [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance)
into the `release` job of the GoReleaser pipeline:

- Sigstore-signed SLSA provenance (keyless, GitHub OIDC → Fulcio) for **every
  released artifact**: each platform archive + the `SHA256SUMS` file.
- Docker image provenance attested **by digest** (GoReleaser surfaces the digest).
- `id-token: write` + `attestations: write` scoped to the `release` job only.
- `gh attestation verify` documented in the README for both binaries and images.

This reaches **Build L2** formally (provenance generated + signed by the
platform, consumer-verifiable). The **L3** isolation/hardening properties are met
*in substance* by GitHub-hosted ephemeral runners + keyless OIDC signing (no
signing secret is ever exposed to build steps), the same posture accepted in
`threatcl/spec`. We do not claim formal L3 certification — there is no third-party
audit of the build platform — but the technical controls are L3-shaped.

---

## Source track (v1.2 — 4 levels)

### Current state

Live state as of 2026-06-27 (`gh api`):

- **Rulesets: none** (`repos/threatcl/threatcl/rulesets` → `[]`).
- **Classic branch protection on `main`** exists but with sharp edges:
  - `required_pull_request_reviews`: 1 approval required.
  - `enforce_admins`: **false** → the solo maintainer (admin) bypasses the entire
    protection, including the PR requirement.
  - `required_signatures`: **false** → commits on `main` are not required to be
    signed (even though the maintainer signs locally).
  - **No required status check** — `make test`/`make vet` is *not* gated on merge.
  - `allow_force_pushes`: false ✅, `allow_deletions`: false ✅.
  - `required_linear_history`: false.
- **Merge settings:** squash, merge-commit, and rebase all allowed (not
  squash-only).
- **No tag protection** — `v*` tags are not immutable.
- **Signing works**: recent `v*` tags are annotated, signed tag objects; commit +
  tag signing is configured locally (SSH signing via Secretive / Secure Enclave).
- **No CODEOWNERS.**

| Source requirement                                                   | Level | Status | Notes |
|----------------------------------------------------------------------|-------|--------|-------|
| Version controlled, stable repo + revision locators, diff tooling    | L1    | 🔶     | GitHub provides all of this; but no **Source VSA** is emitted (GitHub limitation). "L1 in substance." |
| Immutable history — no force-push to `main`                          | L2    | ✅     | `allow_force_pushes=false`, `allow_deletions=false`. |
| Change attribution (who/when/new revision id)                        | L2    | ✅     | Native git + GitHub history. |
| Contemporaneous **Source Provenance** attestations                   | L2    | ⛔     | GitHub does not produce these. |
| Continuous **enforced** technical controls, recorded in attestations | L3    | ⛔     | Controls are bypassable (`enforce_admins=false`), no rulesets, no attestations. |
| Two-party review of every change to protected branches               | L4    | ➖     | Solo maintainer — not achievable without a second trusted reviewer. |

**Honest read:** **Source L1 in substance** (no VSA), with two L2-flavoured
controls (force-push/deletion protection) already in place but neither enforced
against admins nor attested.

### Target state — Source L3 controls, in substance

Phase 2 ports the `threatcl/spec` patterns, committed as importable ruleset JSON
plus a manual import checklist:

- **Branch ruleset on `main`:** require PR, require the test/vet status check,
  block force-push, restrict deletion, linear history, squash-only, **required
  signed commits**.
- **Tag ruleset on `v*`:** immutable + signed tags.
- **CODEOWNERS** so the maintainer is the default reviewer.
- **Solo-maintainer trade-off (deliberate):** use **require-PR-with-0-approvals**
  and *do not* add a bypass actor. A bypass actor skips the **entire** ruleset
  (CI gate, signature requirement, force-push protection — not just review), which
  would defeat the point. 0-required-approvals lets a solo maintainer self-merge
  via PR while still forcing every change through CI + signature + linear-history
  gates.

This enforces the **L3-shaped technical controls** (continuous, non-bypassable,
applied to protected refs). We still **cannot formally claim Source L2/L3**
because GitHub emits **no Source Provenance / VSA** attestations — the spec
requires those to be produced contemporaneously and they simply don't exist yet
on GitHub. We are honest about this gap. **L4 (two-party review) is out of scope**
for a single maintainer.

---

## Supply-chain hygiene (cross-cutting)

These underpin both tracks (a compromised Action can forge provenance or push to
`main`).

| Control                                              | Status | Notes |
|------------------------------------------------------|--------|-------|
| All Actions SHA-pinned with `# vX.Y.Z` comment       | ✅ (Phase 1) | Every `uses:` across all 4 workflows pinned to a full commit SHA + version comment. The lone `@latest` left is inside a commented-out dead block. |
| Dependabot (github-actions + gomod)                  | ✅ (Phase 1) | `.github/dependabot.yml` covers `github-actions`, `gomod`, and `docker` (base images), weekly, grouped. Will drive the older `docker/*` action pins up to current majors as CI-gated PRs. |
| Least-privilege top-level `permissions: contents: read` | ✅ (Phase 1) | All 4 workflows now declare top-level `contents: read` (added to `threatcl-testvet.yml` + `codeql.yml`; already present on the release workflows). |
| Job-scoped escalation only where needed              | ✅ (Phase 1) | Build-only jobs dropped to inherit `contents: read` (they only `upload-artifact`). Escalation kept only on jobs that need it: `release`/`pre-release` (`contents: write`, GitHub Release), image push (`packages: write`). `pre-build-image-test` dropped `packages: write` (it's `push: false`). |
| CodeQL scanning                                      | ✅     | `.github/workflows/codeql.yml` runs on push/PR to `main` + weekly. |

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
| 2     | Branch ruleset on `main` (PR + status check + signed + linear + squash)| Source L2→L3 controls (in substance) | ⛔ |
| 2     | Tag ruleset on `v*` (immutable + signed)                               | Source L2/L3 (tag immutability)  | ⛔ |
| 2     | `CODEOWNERS`                                                           | Source (review routing)          | ⛔ |
| 2     | Require signed commits + status check; drop admin bypass               | Source L3 (enforcement)          | ⛔ |
| 3     | `SHA256SUMS` checksums file in releases                                | Build (integrity)                | ✅ (done in 2.5) |
| 3     | `attest-build-provenance` on every binary + checksums                  | **Build L0→L2 (in substance L3)**| ⛔ |
| 3     | Attest Docker image **by digest**                                      | Build L2 (images)                | ⛔ |
| 3     | README `gh attestation verify` docs (binaries + images-by-digest)      | Build L2 (consumer validation)   | ⛔ |

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

> Filled in during Phase 3 once attestations ship. Will document:
> `gh attestation verify <downloaded-archive> --repo threatcl/threatcl` for
> binaries, and verifying the container image **by digest**.
