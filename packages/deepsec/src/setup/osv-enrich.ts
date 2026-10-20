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
// into the threat-model prompt, so they are collapsed and clamped like summaries
// to block newline/markdown prompt injection.
const MAX_NAME_LENGTH = 120;
const MAX_VERSION_LENGTH = 60;
// uv/osv-scanner reach the network; give them room but never hang setup.
const RESOLVE_TIMEOUT_MS = 120_000;
const OSV_TIMEOUT_MS = 120_000;
// How far below the root to look for dependency manifests.
const MANIFEST_SCAN_DEPTH = 3;
// Range resolution ends: lowest = worst-case/applicable floor, highest = "safe if
// installed today". Scanning both widens coverage of versions the range permits.
const UV_RESOLUTIONS = ["lowest", "highest"] as const;
// A real lockfile next to the manifest means the installed versions are known;
// osv-scanner's recursive walk reads it directly, so skip floor resolution (which
// would otherwise flag hypothetical versions that are not actually installed).
const PYTHON_LOCKFILES = ["uv.lock", "poetry.lock", "Pipfile.lock", "pdm.lock", "requirements.txt"];

interface ResolvedLockfile {
  /** osv-scanner --lockfile spec, e.g. "requirements.txt:/tmp/.../requirements.txt". */
  spec: string;
  /** Temp dir holding the resolved lockfile, removed once osv-scanner has read it. */
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

/**
 * Collect every dependency manifest (pyproject.toml) near the root, skipping
 * vendored and hidden trees. A monorepo can declare several range-only packages;
 * each one needs floor resolution or its CVEs are silently missed.
 */
export function findManifests(projectRoot: string): string[] {
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
      if (entry.isFile() && entry.name === "pyproject.toml") found.push(path.join(dir, entry.name));
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

/** First manifest near the root (kept for callers that only need one). */
export function findManifest(projectRoot: string): string | undefined {
  return findManifests(projectRoot)[0];
}

function hasPythonLockfile(dir: string): boolean {
  return PYTHON_LOCKFILES.some((name) => fs.existsSync(path.join(dir, name)));
}

/**
 * Resolve one manifest at one resolution end into a temp requirements lockfile.
 *
 * uv is run with hardening because the manifest is repository-controlled and
 * resolving it is otherwise arbitrary code execution: `--no-build` blocks PEP 517
 * build hooks and dynamic-metadata project builds, `--no-sources` ignores
 * attacker-controlled `[tool.uv.sources]` (custom index/git/path), and cwd is an
 * empty temp dir so no `uv.toml`/`[tool.uv]` from the project tree is honored.
 * The compile still uses the public index to resolve versions but never executes
 * repo code. Returns undefined (degrading to the source walk) on any failure.
 */
function resolveOne(
  manifest: string,
  resolution: (typeof UV_RESOLUTIONS)[number],
  projectDataDir: string,
  evidenceName: string,
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
    fs.mkdirSync(projectDataDir, { recursive: true });
    fs.copyFileSync(lockfile, path.join(projectDataDir, evidenceName));
    return { spec: `requirements.txt:${lockfile}`, tempDir };
  } catch {
    fs.rmSync(tempDir, { recursive: true, force: true });
    return undefined;
  }
}

/**
 * Many source packages declare dependency *ranges* in a manifest, not a pinned
 * lockfile, so osv-scanner reports "no package sources" and misses every
 * dependency CVE. For each manifest that has no real lockfile, resolve both the
 * lowest and highest allowed versions and hand osv-scanner the resolved
 * lockfiles. Returns the specs to scan, or [] when nothing can be resolved.
 */
function resolveFloorLockfiles(projectRoot: string, projectDataDir: string): ResolvedLockfile[] {
  if (!toolExists("uv")) return [];
  const resolved: ResolvedLockfile[] = [];
  const manifests = findManifests(projectRoot);
  manifests.forEach((manifest, index) => {
    // An authoritative lockfile means the installed versions are known; let the
    // recursive walk read it instead of flagging hypothetical resolved versions.
    if (hasPythonLockfile(path.dirname(manifest))) return;
    for (const resolution of UV_RESOLUTIONS) {
      const suffix = manifests.length > 1 ? `-${index}` : "";
      const r = resolveOne(manifest, resolution, projectDataDir, `deps-${resolution}${suffix}.txt`);
      if (r) resolved.push(r);
    }
  });
  return resolved;
}

/**
 * Run osv-scanner over the project's dependency manifests, persist the result to
 * osv-findings.json, and return a markdown summary of known-vulnerable
 * dependencies for the threat-model prompt.
 *
 * Degrades cleanly: if the required tools are missing it is reported distinctly
 * (no misleading empty artifact), and if osv-scanner finds no sources/advisories
 * the context is empty and setup proceeds unchanged. (osv-scanner exits non-zero
 * when it finds vulnerabilities, so its JSON is read off stdout regardless of
 * exit code.)
 */
export function runOsvEnrich(projectRoot: string, projectDataDir: string): OsvEnrichment {
  if (!toolExists("osv-scanner")) {
    // Distinct from "no vulnerable dependencies": do not write an empty artifact
    // that readers would mistake for a clean result.
    console.warn(
      "[osv-enrich] osv-scanner not found on PATH — skipping dependency-CVE enrichment " +
        "(this is NOT the same as finding no vulnerable dependencies).",
    );
    return { context: "", hits: [] };
  }
  const resolved = resolveFloorLockfiles(projectRoot, projectDataDir);
  let raw = "";
  try {
    const args = ["scan", "source", "-r", "--format", "json", path.resolve(projectRoot)];
    // Scan any resolved floor lockfiles alongside the recursive source walk, so
    // range-only manifests surface their applicable dependency CVEs.
    for (const lockfile of resolved) args.push(`--lockfile=${lockfile.spec}`);
    raw = execFileSync("osv-scanner", args, {
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"],
      timeout: OSV_TIMEOUT_MS,
    });
  } catch (error) {
    const stdout = (error as { stdout?: unknown })?.stdout;
    raw = typeof stdout === "string" ? stdout : "";
  } finally {
    for (const lockfile of resolved) {
      fs.rmSync(lockfile.tempDir, { recursive: true, force: true });
    }
  }
  const hits = parseOsv(raw);
  fs.mkdirSync(projectDataDir, { recursive: true });
  atomicWriteFileSync(
    path.join(projectDataDir, "osv-findings.json"),
    `${JSON.stringify(hits, null, 2)}\n`,
  );
  return { context: buildContext(hits), hits };
}

export function parseOsv(raw: string): OsvPackageHit[] {
  if (!raw.trim()) return [];
  let data: { results?: unknown[] };
  try {
    data = JSON.parse(raw);
  } catch {
    return [];
  }
  // A package can surface from more than one source (e.g. a lowest and a highest
  // resolved lockfile, or osv parsing a pom.xml plus an SBOM). Dedupe by
  // name@version@ecosystem, merging advisories (unique by id).
  const byPackage = new Map<string, OsvPackageHit>();
  for (const result of (data.results ?? []) as Array<{
    source?: { path?: string };
    packages?: unknown[];
  }>) {
    if (VENDORED_SOURCE.test(result.source?.path ?? "")) continue;
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
      } else {
        byPackage.set(key, { name, version, ecosystem: info.ecosystem, vulns });
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
    const vulnLines = h.vulns.map((v) => `  - ${v.id}${v.summary ? `: ${v.summary}` : ""}`);
    return [`- \`${h.name}@${h.version}\``, ...vulnLines].join("\n");
  });
  return [
    "## Known-vulnerable dependencies (from osv-scanner)",
    "",
    "These declared dependencies have published advisories (id followed by what the advisory is about). In the Threat model and Project-specific patterns to flag sections, note where this codebase actually imports or calls each one, so the review can judge whether the advisory is reachable here rather than merely present.",
    "",
    ...blocks,
  ].join("\n");
}
