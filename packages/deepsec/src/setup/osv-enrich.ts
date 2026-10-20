import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { atomicWriteFileSync } from "../atomic-file.js";

export interface OsvVuln {
  id: string;
  /** One-line advisory summary, so the id is self-explanatory. */
  summary?: string;
}

export interface OsvPackageHit {
  name: string;
  version: string;
  ecosystem?: string;
  vulns: OsvVuln[];
  /**
   * True when the version came from a *resolved* floor/ceiling lockfile (uv),
   * not an installed/declared one — i.e. a hypothetical version the range allows,
   * so advisories against it are "applicable if the range resolves there", not
   * confirmed-present. Rendered distinctly so the review doesn't treat an
   * up-to-date project as actually vulnerable.
   */
  resolved?: boolean;
}

export interface OsvEnrichment {
  /** Markdown for the threat-model prompt. Empty when there is nothing to add. */
  context: string;
  hits: OsvPackageHit[];
}

// osv-scanner's recursive walk also descends into deepsec's own workspace and any
// vendored trees, reporting their dependencies as the project's. Drop results
// whose lockfile sits under one of these.
const VENDORED_SOURCE = /(^|\/)(\.deepsec|node_modules|vendor)(\/|$)/;
const MAX_SUMMARY_LENGTH = 160;
// Package name/version come from repo-controlled lockfiles and are interpolated
// into the threat-model prompt, so they are collapsed and clamped to block
// newline/markdown prompt injection.
const MAX_NAME_LENGTH = 120;
const MAX_VERSION_LENGTH = 60;
// Per-subprocess and overall network budgets — these run synchronously, so bound
// the total time rather than relying on an abort signal a blocked call can't see.
const RESOLVE_TIMEOUT_MS = 120_000;
const OSV_TIMEOUT_MS = 120_000;
const OVERALL_RESOLVE_BUDGET_MS = 300_000;
// Cap manifests resolved so a large monorepo can't stall setup for many minutes.
const MAX_MANIFESTS = 10;
// How far below the root to look for dependency manifests.
const MANIFEST_SCAN_DEPTH = 3;
// Range resolution ends: lowest = worst-case/applicable floor, highest = "safe if
// installed today". Scanning both widens coverage of versions the range permits.
const UV_RESOLUTIONS = ["lowest", "highest"] as const;
// Pinned lockfiles next to the manifest mean the installed versions are known;
// osv-scanner's recursive walk reads them directly, so skip floor resolution.
// requirements.txt is intentionally excluded — it is often unpinned (ranges), so
// treating it as authoritative would skip resolution and miss those CVEs.
const PYTHON_LOCKFILES = ["uv.lock", "poetry.lock", "Pipfile.lock", "pdm.lock"];
// PEP 508 direct references (`name @ url`, VCS, local path). Resolving a manifest
// that contains these makes uv fetch attacker-chosen URLs → SSRF, so such
// manifests are skipped rather than resolved.
const DIRECT_REF = /@\s*(https?:\/\/|git\+|hg\+|bzr\+|svn\+|file:|ssh:)/i;

interface ResolvedLockfile {
  /** osv-scanner --lockfile spec, e.g. "requirements.txt:/tmp/.../requirements.txt". */
  spec: string;
  /** Absolute path osv-scanner will report as the result source. */
  sourcePath: string;
  /** Temp dir holding the resolved lockfile, removed once osv-scanner has read it. */
  tempDir: string;
}

interface JavaSbom {
  path: string;
  tempDir: string;
}

/** Whether an executable is on PATH (so a missing tool is distinct from no findings). */
function toolExists(bin: string): boolean {
  try {
    execFileSync(process.platform === "win32" ? "where" : "which", [bin], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/** Collapse whitespace and clamp length — defuses prompt injection via repo-controlled fields. */
function sanitizeField(text: string | undefined, maxLength: number): string {
  if (!text) return "";
  const oneLine = text.replace(/\s+/g, " ").trim();
  return oneLine.length > maxLength ? `${oneLine.slice(0, maxLength - 1)}…` : oneLine;
}

/** The gitignored subdir for regenerable/sensitive setup artifacts. */
function setupDir(projectDataDir: string): string {
  const dir = path.join(projectDataDir, "setup");
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/** Breadth-first walk from the root collecting files named `filename`, skipping
 * vendored and hidden trees. */
function collectFiles(projectRoot: string, filename: string): string[] {
  const found: string[] = [];
  const queue: Array<{ dir: string; depth: number }> = [{ dir: projectRoot, depth: 0 }];
  while (queue.length > 0) {
    const { dir, depth } = queue.shift() as { dir: string; depth: number };
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.isFile() && entry.name === filename) found.push(path.join(dir, entry.name));
    }
    if (depth < MANIFEST_SCAN_DEPTH) {
      for (const entry of entries) {
        if (
          entry.isDirectory() &&
          !entry.name.startsWith(".") &&
          entry.name !== "node_modules" &&
          entry.name !== "vendor"
        ) {
          queue.push({ dir: path.join(dir, entry.name), depth: depth + 1 });
        }
      }
    }
  }
  return found;
}

/** Collect Python manifests near the root (capped). */
export function findManifests(projectRoot: string): string[] {
  return collectFiles(projectRoot, "pyproject.toml").slice(0, MAX_MANIFESTS);
}

/** First Python manifest near the root (kept for callers that only need one). */
export function findManifest(projectRoot: string): string | undefined {
  return findManifests(projectRoot)[0];
}

/** First Maven project file (pom.xml) near the root. */
export function findPom(projectRoot: string): string | undefined {
  return collectFiles(projectRoot, "pom.xml")[0];
}

function hasPythonLockfile(dir: string): boolean {
  return PYTHON_LOCKFILES.some((name) => fs.existsSync(path.join(dir, name)));
}

/** Whether a manifest declares PEP 508 direct URL/VCS/path dependencies (SSRF risk to resolve). */
export function manifestHasDirectRefs(manifest: string): boolean {
  try {
    return DIRECT_REF.test(fs.readFileSync(manifest, "utf8"));
  } catch {
    return false;
  }
}

/**
 * Resolve one manifest at one resolution end into a temp requirements lockfile.
 *
 * uv is hardened because the manifest is repository-controlled: `--no-build`
 * blocks PEP 517 build hooks / dynamic-metadata project builds, `--no-sources`
 * ignores `[tool.uv.sources]`, and cwd is an empty temp dir so no project uv
 * config is honored. (Manifests with inline direct-URL deps are rejected upstream
 * of this.) Returns undefined (degrading to the source walk) on any failure.
 */
function resolveOne(
  manifest: string,
  resolution: (typeof UV_RESOLUTIONS)[number],
  evidencePath: string,
): ResolvedLockfile | undefined {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-osv-"));
  const lockfile = path.join(tempDir, "requirements.txt");
  try {
    execFileSync(
      "uv",
      [
        "pip",
        "compile",
        path.resolve(manifest),
        "--resolution",
        resolution,
        "--no-build",
        "--no-sources",
        "-o",
        lockfile,
        "-q",
      ],
      { cwd: tempDir, stdio: ["ignore", "ignore", "ignore"], timeout: RESOLVE_TIMEOUT_MS },
    );
    if (!fs.existsSync(lockfile)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
      return undefined;
    }
    fs.copyFileSync(lockfile, evidencePath);
    return { spec: `requirements.txt:${lockfile}`, sourcePath: lockfile, tempDir };
  } catch {
    fs.rmSync(tempDir, { recursive: true, force: true });
    return undefined;
  }
}

/**
 * Python packages often declare dependency ranges with no pinned lockfile, so
 * osv-scanner misses their CVEs. For each such manifest, resolve the lowest and
 * highest allowed versions and hand osv-scanner the resolved lockfiles. Skips
 * manifests that have a pinned lockfile (osv reads it) or declare direct-URL deps
 * (resolving them would be an SSRF). Bounded by a manifest cap and an overall
 * time budget since the resolutions run synchronously.
 */
function resolveFloorLockfiles(projectRoot: string, projectDataDir: string): ResolvedLockfile[] {
  if (!toolExists("uv")) {
    const manifests = findManifests(projectRoot).filter((m) => !hasPythonLockfile(path.dirname(m)));
    if (manifests.length > 0) {
      console.warn(
        "[osv-enrich] uv not found on PATH — range-only Python manifests cannot be floor-resolved, " +
          "so their dependency CVEs will be missed (this is NOT the same as finding none).",
      );
    }
    return [];
  }
  const resolved: ResolvedLockfile[] = [];
  const manifests = findManifests(projectRoot);
  const started = Date.now();
  manifests.forEach((manifest, index) => {
    if (Date.now() - started > OVERALL_RESOLVE_BUDGET_MS) return;
    if (hasPythonLockfile(path.dirname(manifest))) return;
    if (manifestHasDirectRefs(manifest)) {
      console.warn(
        `[osv-enrich] skipping floor resolution of ${manifest}: it declares direct-URL/VCS ` +
          "dependencies, which uv would fetch (SSRF risk).",
      );
      return;
    }
    for (const resolution of UV_RESOLUTIONS) {
      if (Date.now() - started > OVERALL_RESOLVE_BUDGET_MS) break;
      const suffix = manifests.length > 1 ? `-${index}` : "";
      const evidence = path.join(setupDir(projectDataDir), `deps-${resolution}${suffix}.txt`);
      const r = resolveOne(manifest, resolution, evidence);
      if (r) resolved.push(r);
    }
  });
  return resolved;
}

/**
 * Maven/Java packages usually pin versions, but osv-scanner can't read a bare
 * pom.xml. syft resolves the Maven project into a CycloneDX SBOM that osv-scanner
 * matches against advisories. syft only catalogs (no build/exec). Returns
 * undefined when there is no pom, syft is missing, or it fails.
 */
function resolveJavaSbom(projectRoot: string, projectDataDir: string): JavaSbom | undefined {
  if (!findPom(projectRoot) || !toolExists("syft")) return undefined;
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-sbom-"));
  const sbom = path.join(tempDir, "deps.cdx.json");
  try {
    execFileSync(
      "syft",
      [
        `dir:${path.resolve(projectRoot)}`,
        "--exclude",
        "./vendor/**",
        "--exclude",
        "./node_modules/**",
        "--exclude",
        "./third_party/**",
        "--exclude",
        "./.deepsec/**",
        "-q",
        "-o",
        `cyclonedx-json=${sbom}`,
      ],
      { stdio: ["ignore", "ignore", "ignore"], timeout: RESOLVE_TIMEOUT_MS },
    );
    if (!fs.existsSync(sbom)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
      return undefined;
    }
    fs.copyFileSync(sbom, path.join(setupDir(projectDataDir), "deps-sbom.cdx.json"));
    return { path: sbom, tempDir };
  } catch {
    fs.rmSync(tempDir, { recursive: true, force: true });
    return undefined;
  }
}

/** Parse osv-scanner JSON (object or raw string); undefined when it isn't a results envelope. */
function parseResultsEnvelope(raw: string): { results?: unknown[] } | undefined {
  if (!raw.trim()) return undefined;
  try {
    const data = JSON.parse(raw);
    return data &&
      typeof data === "object" &&
      Array.isArray((data as { results?: unknown }).results)
      ? (data as { results?: unknown[] })
      : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Run osv-scanner over the project's dependency manifests, persist the result to
 * the gitignored setup/osv-findings.json artifact, and return a markdown summary
 * for the threat-model prompt.
 *
 * Degrades cleanly and reports failures distinctly: a missing tool, or a scan
 * error/timeout, is logged and does NOT overwrite a prior result with an empty
 * one (which would read as "no vulnerable dependencies").
 */
export function runOsvEnrich(projectRoot: string, projectDataDir: string): OsvEnrichment {
  if (!toolExists("osv-scanner")) {
    console.warn(
      "[osv-enrich] osv-scanner not found on PATH — skipping dependency-CVE enrichment " +
        "(this is NOT the same as finding no vulnerable dependencies).",
    );
    return { context: "", hits: [] };
  }
  const resolved = resolveFloorLockfiles(projectRoot, projectDataDir);
  const javaSbom = resolveJavaSbom(projectRoot, projectDataDir);
  let raw = "";
  let timedOut = false;
  try {
    const args = ["scan", "source", "-r", "--format", "json", path.resolve(projectRoot)];
    for (const lockfile of resolved) args.push(`--lockfile=${lockfile.spec}`);
    if (javaSbom) args.push(javaSbom.path);
    raw = execFileSync("osv-scanner", args, {
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"],
      timeout: OSV_TIMEOUT_MS,
    });
  } catch (error) {
    // osv-scanner exits non-zero when it *finds* vulnerabilities (JSON still on
    // stdout) — that's success. Timeouts/crashes are real failures.
    const e = error as { stdout?: unknown; killed?: boolean; signal?: string; code?: string };
    raw = typeof e.stdout === "string" ? e.stdout : "";
    timedOut = Boolean(e.killed) || e.signal === "SIGTERM" || e.code === "ETIMEDOUT";
  } finally {
    for (const lockfile of resolved) fs.rmSync(lockfile.tempDir, { recursive: true, force: true });
    if (javaSbom) fs.rmSync(javaSbom.tempDir, { recursive: true, force: true });
  }

  const envelope = parseResultsEnvelope(raw);
  const noSources = /no package sources/i.test(raw);
  if (timedOut || (!envelope && !noSources)) {
    // Genuine failure — do not persist an empty result over any prior findings.
    console.warn(
      "[osv-enrich] osv-scanner did not complete successfully (timeout or error) — " +
        "leaving any existing osv-findings.json untouched rather than recording a clean result.",
    );
    return { context: "", hits: [] };
  }

  const resolvedPaths = new Set(resolved.map((r) => r.sourcePath));
  const hits = parseOsv(raw, resolvedPaths);
  atomicWriteFileSync(
    path.join(setupDir(projectDataDir), "osv-findings.json"),
    `${JSON.stringify(hits, null, 2)}\n`,
  );
  return { context: buildContext(hits), hits };
}

export function parseOsv(raw: string, resolvedPaths?: Set<string>): OsvPackageHit[] {
  const data = parseResultsEnvelope(raw);
  if (!data) return [];
  // A package can surface from more than one source (e.g. a lowest and a highest
  // resolved lockfile, or osv parsing a pom.xml plus an SBOM). Dedupe by
  // name@version@ecosystem, merging advisories (unique by id).
  const byPackage = new Map<string, OsvPackageHit>();
  for (const result of (data.results ?? []) as Array<{
    source?: { path?: string };
    packages?: unknown[];
  }>) {
    const sourcePath = result.source?.path ?? "";
    if (VENDORED_SOURCE.test(sourcePath)) continue;
    const fromResolved = resolvedPaths?.has(sourcePath) ?? false;
    for (const pkg of (result.packages ?? []) as Array<{
      package?: { name?: string; version?: string; ecosystem?: string };
      vulnerabilities?: Array<{ id?: string; summary?: string; details?: string }>;
    }>) {
      const vulns = (pkg.vulnerabilities ?? [])
        .filter((v): v is { id: string; summary?: string; details?: string } => Boolean(v.id))
        .map((v) => ({ id: v.id, summary: shortSummary(v.summary ?? v.details) }));
      if (vulns.length === 0) continue;
      const info = pkg.package ?? {};
      const name = sanitizeField(info.name, MAX_NAME_LENGTH) || "unknown";
      const version = sanitizeField(info.version, MAX_VERSION_LENGTH) || "unknown";
      const key = `${name}@${version}@${info.ecosystem ?? ""}`;
      const existing = byPackage.get(key);
      if (existing) {
        const seen = new Set(existing.vulns.map((v) => v.id));
        for (const v of vulns) if (!seen.has(v.id)) existing.vulns.push(v);
        // A package is only confirmed-present if some source was a real lockfile.
        if (!fromResolved) existing.resolved = false;
      } else {
        byPackage.set(key, {
          name,
          version,
          ecosystem: info.ecosystem,
          vulns,
          resolved: fromResolved,
        });
      }
    }
  }
  return [...byPackage.values()];
}

function shortSummary(text: string | undefined): string | undefined {
  const sanitized = sanitizeField(text, MAX_SUMMARY_LENGTH);
  return sanitized || undefined;
}

export function buildContext(hits: OsvPackageHit[]): string {
  if (hits.length === 0) return "";
  const blocks = hits.map((h) => {
    // Floor/ceiling versions are hypothetical (not installed), so mark them so the
    // review doesn't treat a patched project as actually vulnerable.
    const marker = h.resolved ? " (resolved range version — not necessarily installed)" : "";
    const vulnLines = h.vulns.map((v) => `  - ${v.id}${v.summary ? `: ${v.summary}` : ""}`);
    return [`- \`${h.name}@${h.version}\`${marker}`, ...vulnLines].join("\n");
  });
  return [
    "## Known-vulnerable dependencies (from osv-scanner)",
    "",
    'These dependencies have published advisories (id followed by what the advisory is about). Rows marked "resolved range version" come from resolving a version range and may not be the installed version — treat them as applicable-if-resolved, not confirmed-present. In the Threat model and Project-specific patterns to flag sections, note where this codebase actually imports or calls each one, so the review can judge whether the advisory is reachable here rather than merely present.',
    "",
    ...blocks,
  ].join("\n");
}
