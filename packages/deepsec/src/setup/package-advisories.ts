import fs from "node:fs";
import path from "node:path";
import { atomicWriteFileSync } from "../atomic-file.js";
import { collectFiles, PACKAGE_CONTEXT_HEADING } from "./osv-enrich.js";

/**
 * Advisories for the scanned package itself (not its dependencies) that come
 * from releases newer than the one being scanned. Two kinds:
 *
 * - in range: OSV says this version is affected and a newer release fixed it;
 * - newer only: OSV records the advisory only against newer releases, but the
 *   same vulnerable code may also exist in this older version — an applicable
 *   advisory nobody recorded for it.
 *
 * Advisories fixed before this version are dropped; they're already behind it.
 * Each one kept goes into the threat model so matchers target the vulnerable
 * code and the investigation decides whether this codebase is affected.
 */

export const PACKAGE_ADVISORY_HEADING = "### Package advisories from newer releases";

export interface PackageIdentity {
  name: string;
  version: string;
  ecosystem: "PyPI" | "Maven";
  /** Where the name/version were read from, relative to the project root. */
  source: string;
}

export interface PackageAdvisory {
  id: string;
  aliases: string[];
  summary?: string;
  /** Fixed versions recorded by OSV (may be empty when there's no fix yet). */
  fixed: string[];
  /** Earliest version OSV records as affected, when known. */
  introduced?: string;
  kind: "in-range" | "newer-only";
}

export interface PackageAdvisoryResult {
  identity?: PackageIdentity;
  advisories: PackageAdvisory[];
  /** Markdown for the threat-model prompt. Empty when there's nothing to add. */
  context: string;
}

const OSV_QUERY_URL = "https://api.osv.dev/v1/query";
const OSV_TIMEOUT_MS = 30_000;
// Keep the threat-model prompt bounded: a package with a long advisory history
// shouldn't crowd out the code threats.
const MAX_IN_RANGE = 15;
const MAX_NEWER_ONLY = 10;
const MAX_TEXT = 220;
const MAX_FIELD = 120;

/** Collapse whitespace and clamp — OSV text is third-party and goes into a prompt. */
function clean(text: string | undefined, max: number): string {
  if (!text) return "";
  const one = text.replace(/\s+/g, " ").trim();
  return one.length > max ? `${one.slice(0, max - 1)}…` : one;
}

function readFirst(
  projectRoot: string,
  filename: string,
): { file: string; text: string } | undefined {
  for (const file of collectFiles(projectRoot, filename)) {
    if (file.includes(`${path.sep}.deepsec${path.sep}`)) continue;
    try {
      return { file, text: fs.readFileSync(file, "utf8") };
    } catch {}
  }
  return undefined;
}

/**
 * The scanned package's own name and version, from static metadata only (no
 * build, no code execution): PKG-INFO (every sdist has one), then a static
 * [project] table in pyproject.toml, then a Maven pom.xml.
 */
export function detectPackageIdentity(projectRoot: string): PackageIdentity | undefined {
  const rel = (file: string) => path.relative(projectRoot, file) || path.basename(file);
  const pkgInfo = readFirst(projectRoot, "PKG-INFO");
  if (pkgInfo) {
    const name = pkgInfo.text.match(/^Name:\s*(.+)$/m)?.[1]?.trim();
    const version = pkgInfo.text.match(/^Version:\s*(.+)$/m)?.[1]?.trim();
    if (name && version) {
      return {
        name: clean(name, MAX_FIELD),
        version: clean(version, MAX_FIELD),
        ecosystem: "PyPI",
        source: rel(pkgInfo.file),
      };
    }
  }
  const pyproject = readFirst(projectRoot, "pyproject.toml");
  if (pyproject) {
    const table = pyproject.text.match(/^\[project\]\s*$([\s\S]*?)(?=^\[|$(?![\s\S]))/m)?.[1] ?? "";
    const name = table.match(/^\s*name\s*=\s*["']([^"']+)["']/m)?.[1];
    const version = table.match(/^\s*version\s*=\s*["']([^"']+)["']/m)?.[1];
    if (name && version) {
      return {
        name: clean(name, MAX_FIELD),
        version: clean(version, MAX_FIELD),
        ecosystem: "PyPI",
        source: rel(pyproject.file),
      };
    }
  }
  const pom = readFirst(projectRoot, "pom.xml");
  if (pom) {
    // Drop the <parent> block so its coordinates aren't mistaken for the project's.
    const body = pom.text.replace(/<parent>[\s\S]*?<\/parent>/, "");
    const groupId = body.match(/<groupId>([^<]+)<\/groupId>/)?.[1]?.trim();
    const artifactId = body.match(/<artifactId>([^<]+)<\/artifactId>/)?.[1]?.trim();
    const version = body.match(/<version>([^<]+)<\/version>/)?.[1]?.trim();
    if (groupId && artifactId && version && !version.includes("${")) {
      return {
        name: clean(`${groupId}:${artifactId}`, MAX_FIELD),
        version: clean(version, MAX_FIELD),
        ecosystem: "Maven",
        source: rel(pom.file),
      };
    }
  }
  return undefined;
}

/**
 * Compare two release versions by their numeric parts (1.10 > 1.9). Returns
 * undefined when either isn't a plain dotted number, so callers skip rather
 * than guess on pre-releases, dates with letters, or git refs.
 */
export function compareVersions(a: string, b: string): number | undefined {
  const parse = (v: string) => (/^\d+(\.\d+)*$/.test(v) ? v.split(".").map(Number) : undefined);
  const x = parse(a);
  const y = parse(b);
  if (!x || !y) return undefined;
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

interface OsvVulnRecord {
  id?: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  affected?: Array<{
    ranges?: Array<{ type?: string; events?: Array<{ introduced?: string; fixed?: string }> }>;
  }>;
}

function events(v: OsvVulnRecord): { introduced: string[]; fixed: string[] } {
  const introduced: string[] = [];
  const fixed: string[] = [];
  for (const a of v.affected ?? []) {
    for (const r of a.ranges ?? []) {
      if (r.type && r.type !== "ECOSYSTEM" && r.type !== "SEMVER") continue;
      for (const e of r.events ?? []) {
        if (e.introduced && e.introduced !== "0") introduced.push(e.introduced);
        if (e.introduced === "0") introduced.push("0");
        if (e.fixed) fixed.push(e.fixed);
      }
    }
  }
  return { introduced, fixed };
}

/**
 * Split the package's advisories into the two kinds we keep. `inRangeIds` is
 * OSV's own answer for "affects this version" (the authoritative version
 * query); the newer-only set is every other advisory whose earliest affected
 * version is newer than ours.
 */
export function classifyAdvisories(
  all: OsvVulnRecord[],
  inRangeIds: Set<string>,
  version: string,
): PackageAdvisory[] {
  const out: PackageAdvisory[] = [];
  const seen = new Set<string>();
  for (const v of all) {
    if (!v.id || seen.has(v.id)) continue;
    // GHSA and PYSEC often describe the same CVE; keep one entry per alias group.
    const group = [v.id, ...(v.aliases ?? [])];
    if (group.some((id) => seen.has(id))) continue;
    const { introduced, fixed } = events(v);
    const summary = clean(v.summary || v.details, MAX_TEXT) || undefined;
    const base = {
      id: clean(v.id, MAX_FIELD),
      aliases: (v.aliases ?? []).map((a) => clean(a, MAX_FIELD)),
      summary,
      fixed: [...new Set(fixed)].map((f) => clean(f, MAX_FIELD)),
    };
    let kind: PackageAdvisory["kind"] | undefined;
    if (inRangeIds.has(v.id) || (v.aliases ?? []).some((a) => inRangeIds.has(a))) {
      kind = "in-range";
    } else {
      const starts = introduced.filter((i) => i !== "0").map((i) => compareVersions(i, version));
      // Every recorded range starts after this version → reported only for newer releases.
      if (starts.length > 0 && starts.every((c) => c !== undefined && c > 0)) kind = "newer-only";
    }
    if (!kind) continue;
    const earliest = introduced
      .filter((i) => i !== "0")
      .sort((a, b) => compareVersions(a, b) ?? 0)[0];
    out.push({ ...base, kind, ...(earliest ? { introduced: clean(earliest, MAX_FIELD) } : {}) });
    for (const id of group) seen.add(id);
  }
  return out;
}

async function osvQuery(body: unknown, fetchImpl: typeof fetch): Promise<OsvVulnRecord[]> {
  const res = await fetchImpl(OSV_QUERY_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(OSV_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`OSV returned HTTP ${res.status}`);
  const data = (await res.json()) as { vulns?: OsvVulnRecord[] };
  return data.vulns ?? [];
}

export function buildPackageAdvisoryContext(
  identity: PackageIdentity,
  advisories: PackageAdvisory[],
): string {
  const inRange = advisories.filter((a) => a.kind === "in-range").slice(0, MAX_IN_RANGE);
  const newerOnly = advisories.filter((a) => a.kind === "newer-only").slice(0, MAX_NEWER_ONLY);
  if (inRange.length === 0 && newerOnly.length === 0) return "";
  const line = (a: PackageAdvisory, where: string) =>
    `- ${a.id}${a.aliases.length ? ` (${a.aliases.join(", ")})` : ""} — ${where}${a.summary ? `: ${a.summary}` : ""}`;
  const lines = [
    PACKAGE_CONTEXT_HEADING,
    "",
    `The package being scanned is \`${identity.name}@${identity.version}\` (${identity.ecosystem}, read from ${identity.source}). These are advisories for this package itself from releases newer than this version.`,
    "",
  ];
  if (inRange.length) {
    lines.push("OSV records this version as affected; a newer release fixed it:", "");
    for (const a of inRange)
      lines.push(
        line(a, a.fixed.length ? `fixed in ${a.fixed.join(", ")}` : "no fix released yet"),
      );
    lines.push("");
  }
  if (newerOnly.length) {
    lines.push(
      "OSV records these only against newer releases. The same vulnerable code may still exist in this older version:",
      "",
    );
    for (const a of newerOnly)
      lines.push(
        line(
          a,
          `recorded from ${a.introduced ?? "a newer release"}${a.fixed.length ? `, fixed in ${a.fixed.join(", ")}` : ""}`,
        ),
      );
    lines.push("");
  }
  lines.push(
    `${PACKAGE_ADVISORY_HEADING} (required)`,
    "",
    `In the Threat model section, emit a \`Package advisories from newer releases\` subsection with exactly one line for EVERY advisory above — do not omit any or merge them into prose. Use this fixed format per line:`,
    "",
    "`- <id> — <fixed in X | recorded from X> — <LIKELY AFFECTED|CHECK|LIKELY NOT PRESENT> — <file:line of the vulnerable code in this codebase, or why it is absent> — <impact if affected>`",
    "",
    "Grade by reading this codebase, not the version number: LIKELY AFFECTED when the vulnerable code is present and unpatched (name the `file:line`), LIKELY NOT PRESENT when the vulnerable feature doesn't exist here or the fix is already applied (say which), CHECK when you can't tell yet. For advisories OSV records only against newer releases, look for the same vulnerable code in this version — if it is here, this version is affected even though no advisory says so.",
  );
  return lines.join("\n");
}

/**
 * Look up the scanned package's own advisories and return the threat-model
 * context. Network failure or an unknown package degrades to no context with a
 * warning (never reads as "no advisories").
 */
export async function runPackageAdvisories(
  projectRoot: string,
  projectDataDir: string,
  fetchImpl: typeof fetch = fetch,
): Promise<PackageAdvisoryResult> {
  const identity = detectPackageIdentity(projectRoot);
  if (!identity) {
    console.warn(
      "[package-advisories] couldn't read the package's own name and version (no PKG-INFO, static pyproject, or pom.xml) — skipping its advisory lookup.",
    );
    return { advisories: [], context: "" };
  }
  let all: OsvVulnRecord[];
  let inRange: OsvVulnRecord[];
  try {
    const pkg = { name: identity.name, ecosystem: identity.ecosystem };
    [all, inRange] = await Promise.all([
      osvQuery({ package: pkg }, fetchImpl),
      osvQuery({ package: pkg, version: identity.version }, fetchImpl),
    ]);
  } catch (error) {
    console.warn(
      `[package-advisories] OSV lookup for ${identity.name}@${identity.version} failed (${error instanceof Error ? error.message : String(error)}) — its advisories are not checked (this is NOT the same as none).`,
    );
    return { identity, advisories: [], context: "" };
  }
  const inRangeIds = new Set(
    inRange.flatMap((v) => [v.id ?? "", ...(v.aliases ?? [])]).filter(Boolean),
  );
  const advisories = classifyAdvisories(all, inRangeIds, identity.version);
  const dir = path.join(projectDataDir, "setup");
  fs.mkdirSync(dir, { recursive: true });
  atomicWriteFileSync(
    path.join(dir, "package-advisories.json"),
    `${JSON.stringify({ identity, advisories }, null, 2)}\n`,
  );
  return { identity, advisories, context: buildPackageAdvisoryContext(identity, advisories) };
}
