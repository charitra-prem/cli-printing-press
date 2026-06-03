---
date: 2026-06-04
topic: request-evidence-pr7-roadmap-from-live-slack-test
supersedes-section: docs/brainstorms/2026-06-02-request-evidence-requirements.md#out-of-scope
---

# Request-Evidence: PR 7+ Roadmap from Live Slack Test

## Context

The fork landed PRs 1–6 of the [request-evidence plan](2026-06-02-request-evidence-requirements.md) on 2026-06-03 and merged to `main`. On 2026-06-04 I ran a fresh live test against Slack desktop (2 chats opened, 28 captured entries across 3 hosts) and exercised the full pipeline end to end: `mitmdump --mode local:Slack` → `browser-sniff` → `generate` → printed CLI invocation.

Three things worked as designed (per-endpoint host preservation, cookie session-header, evidence sidecar emission). Five things failed live in ways the test harness never exercised. The post-implementation review was run through `codex exec` — its strongest opinion and the recommended PR 7+ shape follow.

## Live-test findings

### Worked

- **Per-endpoint host preservation (PR 2).** `cache-resource` correctly routed to `edgeapi.slack.com`; everything else to `premai.slack.com`. No manual `--preserve-hosts`.
- **Cookie env var loading (PR 1).** `SLACK_COOKIES='d=xoxd-...; ...'` (multi-pair session header) was attached without the net/http `;`-in-`Cookie.Value` warning that broke the original 2026-06-02 experiment.
- **Evidence sidecar (PR 4).** `spec-request-evidence.json` emitted alongside the spec with full per-slot 5-class classification.
- **Validation gate ordering (PR 6).** Ran first in `Validate()`, well under 1s.

### Failed

1. **Body fields missing from CLI surface (blocker for actual use).** The printed `conversations.history` ships `body := map[string]any{}`. The captured wire body had `token` (auth-secret-classed), `channel`, `limit`, `oldest`, `cached_latest_updates`, and 11 more form fields — none reach `spec.yaml` as endpoint params. PR 3's parser works in unit tests; the live HAR-to-spec path doesn't carry body fields through. The PR 3 golden case (httpbin) has no POST bodies, so the gap never surfaced in CI.

2. **Volatile-drop classification not applied to CLI surface.** `conversations.history` exposes 12 flags (`--x-b3-sampled`, `--x-csid`, `--fp`, `--slack-route`, etc.) — every one classified `volatile-drop` by PR 4's classifier. The sidecar correctly identifies them; the generator's flag walker doesn't consult the classification. Same wiring gap as #1: classifier metadata exists, generator doesn't read it.

3. **`cache` reserved-name collision.** Every Slack capture (and any native app with a `/cache/` route) hits a parse-time hard error in `generate`. Plan flagged this as out-of-scope; live workflow shows it's the first thing every fresh sniffed CLI hits.

4. **`cookie_domain` bound to one host.** Generated spec emits `cookie_domain: .edgeapi.slack.com`. Slack's session cookie is shared across `*.slack.com`. Pinning to one subdomain prevents press-auth from finding the cookie in a browser jar.

5. **Body fields appear only as response type fields.** `channel`, `token`, `limit` show up inside `types:` blocks (response type inference) but never as `Endpoint.Body` entries. Two parallel body-handling paths exist; only one is fed by the live HAR converter.

## Codex review

Full output: see `git show HEAD -- docs/brainstorms/2026-06-04-codex-review.txt` (committed alongside this plan). Strongest opinion verbatim:

> **Make evidence the sniffed wire authority, but do not fork request templates. Project evidence into `spec.APISpec` before rendering, then keep the existing CLI/MCP walkers unified.**

This corrects an implicit assumption in PR 5: that the evidence sidecar would be consumed via a `{{if .RequestEvidence}}` template branch. The live test shows that approach would force every walker (CLI flags, MCP tools, `tools-manifest.json`, README examples, required-input checks) to gain a parallel evidence-aware path. Codex's recommendation is the inverse: spec.yaml stays the generator's IR, but evidence overlays it (mutating in-memory) before any walker runs. PR 5 already did this for `BaseURL` via `applyRequestEvidence::overlayEvidenceBaseURLs`. The same overlay extends to request shape.

## PR 7+ roadmap

Six PRs. Ordered by blast radius (1, 4 unblock daily use; 2, 5 close the wire-fidelity loop; 3, 6 are the long arc).

### PR 7 — Body-field projection through the HAR path

**Goal:** Live HAR captures emit form/multipart body fields into `spec.Endpoint.Body` so the generator's existing body walker picks them up unmodified.

**Files:** `internal/browsersniff/types.go` (model `HARPostData.params`), `internal/browsersniff/parser.go::convertHAREntry` (synthesize `RequestBody`, backfill `Content-Type` from `postData.mimeType`), `internal/browsersniff/specgen.go::{inferRequestBody, dominantBodyContentType, buildEndpoint}` (route parsed fields into `Endpoint.Body` with `Param.ContentLocation` + `Param.Classification`).

**No template changes.** The generator already has `bodyFlagRegs`, `multipartBodyMaps`, `formBodyMaps`, `isAuthSecretBodyParam` (added in PR 3) — they just don't see populated bodies today.

**Acceptance:** generated `conversations.history` has `--channel`, `--limit`, `--oldest` flags + `$TOKEN` env-var requirement (not a `--token` flag). New golden fixture: redacted Slack-shaped HAR.

### PR 8 — Reserved-name auto-rename

**Goal:** No more `cache → cache_resource` hand-edits. Every sniffed CLI generates cleanly.

**Files:** `internal/spec/spec.go::applyReservedResourceParentPrefixes` (existing helper handles parent-prefixable cases — extend with a deterministic fallback for bare reserved resources before `validateReservedNames`, using `ReservedCLIResourceNames` and collision-aware suffixing: `cache_resource`, `cache_resource_2`, ...). Update references via `rewriteResourceReferences`.

**Affects all input modes.** Not sniff-specific. Highest workflow-friction reduction per line of code.

### PR 9 — Volatile-slot suppression upstream of spec emission

**Goal:** Volatile slots stay in the sidecar (audit trail) but never reach `spec.yaml`, so they never become flags, MCP tools, or README examples.

**Files:** `internal/wireevidence/classifier.go::ClassifySlot` (extend beyond header names to query+body name patterns: `x-csid`, `fp`, `slack_route`, trace IDs, retry IDs, build timestamps). `internal/browsersniff/specgen.go::inferURLParams` and the body-projection path from PR 7 consult the classifier and skip `volatile-drop` slots when building `Endpoint.Params` / `Endpoint.Body`.

**Acceptance:** `conversations.history` drops from 12 flags to ~5. Sidecar still records the volatile slots with classification, so the validation gate can verify they're correctly absent from the CLI surface.

### PR 10 — Cookie-domain inference via publicsuffix

**Goal:** `cookie_domain` is the registrable root, not one captured subdomain.

**Files:** `internal/browsersniff/reachability.go::reachabilityCookieDomain` and `internal/browsersniff/specgen.go::detectCapturedAuth` (use existing `golang.org/x/net/publicsuffix.EffectiveTLDPlusOne` — already imported by `analysis.go:1311`). `.edgeapi.slack.com` → `.slack.com`; `.app.notion.so` → `.notion.so`.

**Acceptance:** new unit test pinning domain reduction for the common cases; press-auth's Chrome cookie extractor finds session cookies from any subdomain of the registered root.

### PR 11 — `overlayEvidenceRequestShape` pass

**Goal:** Promote `applyRequestEvidence` from "overlay BaseURL only" to "overlay the full request shape." Evidence becomes the wire authority for sniffed sources; spec.yaml is the generator IR.

**Files:** `internal/generator/evidence_embed.go::applyRequestEvidence` — extend from `overlayEvidenceBaseURLs` to `overlayEvidenceRequestShape`: repair `Endpoint.{BaseURL, Params, Body, RequestContentType, HeaderOverrides}`, defaults, and auth-secret classifications from sidecar slots before `buildPromotedCommandPlan` runs.

**Depends on:** PR 7 (body projection in place so the spec already has the shape; overlay only repairs drift).

### PR 12 — Strengthen validation gate to assert surface coverage

**Goal:** PR 6's gate checks slot reconstruction matches exemplars but doesn't check the CLI surface covers the captured wire. "Missing `--channel`" should fail validation.

**Files:** `internal/generator/validate_evidence.go::validateRequestEvidence` — add a second assertion: every non-volatile evidence slot is represented somewhere in the rendered `APISpec` surface (param, body field, header override, or auth env var). Every `volatile-drop` slot is **absent** from the surface.

**Depends on:** PR 11 (so the overlay runs first and surface is consistent with evidence by the time validation fires).

**Acceptance:** reverting any of PRs 7, 9, 10, 11 individually makes the gate fire. Slack capture round-trips cleanly: capture → generate → validate → live API call without hand-edits.

## Sequencing

- **PR 7 + PR 8 unblock daily use.** No dependencies; both parallel-safe.
- **PR 9 depends on PR 7** (body projection has to exist before the classifier can drop volatile body slots).
- **PR 10 is standalone.** Parallel-safe with everything.
- **PR 11 depends on PR 7 and PR 9** (overlay needs the body shape and volatile suppression in place).
- **PR 12 depends on PR 11** (validation asserts what the overlay produced).

## Testing approach (codex's #5)

Drive PR 7+ by **live-output proof, not unit-level scaffolding**:

- Commit a redacted Slack-shaped HAR fixture (`testdata/sniff/slack-redacted.har`): multipart `postData.params`, multi-host routing, volatile query keys, cookie auth, `xoxc-...`-shaped body tokens.
- New golden case: `browser-sniff` against that fixture; assert the emitted `spec.yaml` has body params with `content_location: body_multipart` and `classification: auth-secret` for the token.
- New generator-output test: build the printed CLI from that spec, inspect emitted flags (assert `--channel` present, `--x-b3-traceid` absent, env-var requirement for the token).

The 2026-06-02 plan's unit-level coverage was correct but too narrow — the httpbin golden has no POST bodies and no volatile params. The browser-sniff-sample golden is the only end-to-end fixture and it doesn't exercise either of the two failure modes the live test surfaced.

## Open questions deferred

- **Per-API env-var prefix for auth-secret body fields.** PR 3 used bare wire names (`$TOKEN` for the Slack token). PR 5 deferred per-API prefixing (`$SLACK_TOKEN`). Should land in PR 7 — codegen has API context by then.
- **MCP tools and tools-manifest.json shape with the new overlay.** PR 11 must verify the same overlay runs before MCP descriptor emission, not just CLI flag emission.
- **What to do with the Slack capture's `_x_*` cookie auth detection.** The capture set `cookie_domain: .edgeapi.slack.com`. With PR 10 this becomes `.slack.com`. Worth a regression test against the original 2026-06-02 experiment artifacts if they can be re-captured.
