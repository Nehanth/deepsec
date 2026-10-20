---
title: "Dependency CVEs"
description: "Surface known-vulnerable dependencies during setup with the opt-in osv step, for Python ranges and Java/Maven projects."
---

deepsec can surface known-vulnerable dependencies (CVEs) alongside its usual code review. The step is **off by default**. When you enable it, setup runs `osv-scanner` over the project's dependencies, feeds any advisories into the threat model, and steers matcher generation toward the vulnerable call sites so a reachable advisory becomes a located finding rather than a flat list entry.

## Enable it

Turn it on per run with the flag:

```bash
deepsec setup --osv
# or on a fresh workspace
deepsec init --osv
```

Or persist it per project in `deepsec.config.ts`:

```ts
export default defineConfig({
  projects: [{ id: "api", root: ".", osv: true }],
});
```

Either form enables the step; the default remains off because it runs external tools that reach the network during setup. Enabling it invalidates only that project's threat-model checkpoint, so the next `setup` re-runs the `info` phase once to incorporate the advisories.

## Required tools

The step calls external binaries and degrades cleanly when they are absent (it logs a warning and skips, which is distinct from reporting no vulnerabilities):

| Tool | Needed for | If missing |
|---|---|---|
| `osv-scanner` | the scan itself | the whole step is skipped |
| `uv` | resolving range-only Python manifests | those Python CVEs are skipped; pinned lockfiles still scanned |
| `syft` | resolving Java/Maven projects | the `pom.xml` is not scanned |

## What it covers

**Lockfiles.** Any lockfile `osv-scanner` already understands (`package-lock.json`, `go.mod`, a pinned `requirements.txt`, and so on) is scanned directly during the recursive source walk.

**Python ranges.** `osv-scanner` can't read a `pyproject.toml` that declares version ranges with no lockfile. When `uv` is available, deepsec resolves such a manifest to both its **lowest** and **highest** allowed versions with `uv pip compile` and scans those. The lowest version is the worst case a `>=` constraint permits; the highest is what a fresh install gets today. Manifests that already have a pinned lockfile (`uv.lock`, `poetry.lock`, `Pipfile.lock`, `pdm.lock`) are left to the direct scan.

**Java/Maven.** `osv-scanner` can't read a bare `pom.xml` either. When `syft` is available, deepsec resolves the Maven project into a CycloneDX SBOM and scans that. Gradle projects without a lockfile are not resolved.

## How results appear

- `data/<id>/setup/osv-findings.json` records the vulnerable packages and their advisory IDs. This file and the resolver's evidence files live under the gitignored `setup/` directory.
- The threat model (`INFO.md`) gains a **Known-vulnerable dependencies** section. Rows resolved from a version range are labeled as such, since that version may not be the one installed.
- Matcher generation receives the threat model, so an advisory whose vulnerable call is reachable in the code gets a matcher and becomes a scan candidate. The investigation phase then judges reachability and writes the finding.

## Security notes

The resolver treats the manifest as untrusted input. `uv` runs with `--no-build` and `--no-sources` and in an empty working directory, so it resolves versions without executing project build hooks or honoring attacker-controlled sources. A manifest that declares direct-URL or VCS dependencies is skipped rather than resolved, because resolving it would fetch attacker-chosen URLs. Package names and versions are sanitized before they reach the prompt.

## Limitations

- Range resolution checks the lowest and highest allowed versions, not every version in between, so an advisory that affects only a middle version (introduced and fixed inside the range) can be missed.
- A resolved version is hypothetical: it is what the range permits, not necessarily what is installed. Findings from resolved versions are applicable-if-resolved, not confirmed-present, which is why the threat model labels them.
