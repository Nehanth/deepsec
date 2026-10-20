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
// uv reaches the index to resolve a manifest; give it room but don't hang setup.
const RESOLVE_TIMEOUT_MS = 120_000;
// How far below the root to look for a dependency manifest.
const MANIFEST_SCAN_DEPTH = 3;

interface ResolvedLockfile {
  /** osv-scanner --lockfile spec, e.g. "requirements.txt:/tmp/.../requirements.txt". */
  spec: string;
  /** Temp dir holding the resolved lockfile, removed once osv-scanner has read it. */
  tempDir: string;
}

/** Breadth-first walk from the root for the first file named `filename`, skipping
 * vendored and hidden trees. */
function findFileNear(projectRoot: string, filename: string): string | undefined {
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
      if (entry.isFile() && entry.name === filename) return path.join(dir, entry.name);
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
  return undefined;
}

/** Find a Python dependency manifest (pyproject.toml) near the root. */
export function findManifest(projectRoot: string): string | undefined {
  return findFileNear(projectRoot, "pyproject.toml");
}

/** Find a Maven project file (pom.xml) near the root. */
export function findPom(projectRoot: string): string | undefined {
  return findFileNear(projectRoot, "pom.xml");
}

/**
 * Many source packages declare dependency *ranges* in a manifest, not a pinned
 * lockfile, so osv-scanner reports "no package sources" and misses every
 * dependency CVE. Resolve the manifest to its lowest allowed versions — the
 * worst-case / applicable-CVE floor (a `>=` constraint permits a build to land
 * on that floor) — and hand osv-scanner the resolved lockfile.
 *
 * The lockfile goes in a temp dir (not projectDataDir) so its osv source path is
 * not mistaken for a vendored tree; a copy is kept as deps-lowest.txt evidence.
 * Returns the specs to pass to osv-scanner, or [] when nothing can be resolved.
 */
function resolveFloorLockfiles(projectRoot: string, projectDataDir: string): ResolvedLockfile[] {
  const manifest = findManifest(projectRoot);
  if (!manifest) return [];
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-osv-"));
  const lockfile = path.join(tempDir, "requirements.txt");
  try {
    execFileSync(
      "uv",
      ["pip", "compile", manifest, "--resolution", "lowest", "-o", lockfile, "-q"],
      { stdio: ["ignore", "ignore", "ignore"], timeout: RESOLVE_TIMEOUT_MS },
    );
    if (!fs.existsSync(lockfile)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
      return [];
    }
    // Keep the resolved floor as evidence alongside osv-findings.json.
    fs.mkdirSync(projectDataDir, { recursive: true });
    fs.copyFileSync(lockfile, path.join(projectDataDir, "deps-lowest.txt"));
    return [{ spec: `requirements.txt:${lockfile}`, tempDir }];
  } catch {
    // uv missing, manifest unresolvable, or timed out: fall back to source scan.
    fs.rmSync(tempDir, { recursive: true, force: true });
    return [];
  }
}

interface JavaSbom {
  /** CycloneDX SBOM file for osv-scanner to scan (auto-detected by the .cdx.json name). */
  path: string;
  /** Temp dir holding the SBOM, removed once osv-scanner has read it. */
  tempDir: string;
}

/**
 * Maven/Java packages usually pin dependency versions (no ranges to floor-
 * resolve), but osv-scanner can't read a bare pom.xml ("no package sources").
 * Mirror Traust's SBOM step: syft resolves the Maven project into a CycloneDX
 * SBOM, which osv-scanner then matches against advisories. Excludes mirror the
 * vendored-tree filter. A copy of the SBOM is kept as evidence.
 *
 * Degrades cleanly: no pom, syft missing, or syft fails → undefined, and the
 * scan falls back to the source walk unchanged.
 */
function resolveJavaSbom(projectRoot: string, projectDataDir: string): JavaSbom | undefined {
  if (!findPom(projectRoot)) return undefined;
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
    fs.mkdirSync(projectDataDir, { recursive: true });
    fs.copyFileSync(sbom, path.join(projectDataDir, "deps-sbom.cdx.json"));
    return { path: sbom, tempDir };
  } catch {
    fs.rmSync(tempDir, { recursive: true, force: true });
    return undefined;
  }
}

/**
 * Run osv-scanner over the project's dependency manifests, persist the result to
 * osv-findings.json, and return a markdown summary of known-vulnerable
 * dependencies for the threat-model prompt.
 *
 * Degrades cleanly: if osv-scanner is missing, finds no recognized package
 * sources, or reports no advisories, the context is empty and setup proceeds
 * unchanged. (osv-scanner exits non-zero when it finds vulnerabilities, so its
 * JSON is read off stdout regardless of exit code.)
 */
export function runOsvEnrich(projectRoot: string, projectDataDir: string): OsvEnrichment {
  const resolved = resolveFloorLockfiles(projectRoot, projectDataDir);
  const javaSbom = resolveJavaSbom(projectRoot, projectDataDir);
  let raw = "";
  try {
    const args = ["scan", "source", "-r", "--format", "json", path.resolve(projectRoot)];
    // Scan any resolved floor lockfiles alongside the recursive source walk, so
    // range-only manifests surface their applicable dependency CVEs.
    for (const lockfile of resolved) args.push(`--lockfile=${lockfile.spec}`);
    // A Maven project's SBOM (from syft) carries the Java deps osv-scanner can't
    // read from a bare pom.xml; it is auto-detected by its .cdx.json name.
    if (javaSbom) args.push(javaSbom.path);
    raw = execFileSync("osv-scanner", args, {
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch (error) {
    const stdout = (error as { stdout?: unknown })?.stdout;
    raw = typeof stdout === "string" ? stdout : "";
  } finally {
    for (const lockfile of resolved) {
      fs.rmSync(lockfile.tempDir, { recursive: true, force: true });
    }
    if (javaSbom) fs.rmSync(javaSbom.tempDir, { recursive: true, force: true });
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
  // The same dependency can surface from more than one source — e.g. osv-scanner
  // parses a simple pom.xml during the recursive walk AND the syft SBOM catches
  // it too. Dedupe by name@version@ecosystem, merging advisories (unique by id).
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
      const name = info.name ?? "unknown";
      const version = info.version ?? "unknown";
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
  if (!text) return undefined;
  const oneLine = text.replace(/\s+/g, " ").trim();
  if (!oneLine) return undefined;
  return oneLine.length > MAX_SUMMARY_LENGTH
    ? `${oneLine.slice(0, MAX_SUMMARY_LENGTH - 1)}…`
    : oneLine;
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
