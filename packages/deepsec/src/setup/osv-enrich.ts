import { execFileSync } from "node:child_process";
import fs from "node:fs";
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
  let raw = "";
  try {
    raw = execFileSync(
      "osv-scanner",
      ["scan", "source", "-r", "--format", "json", path.resolve(projectRoot)],
      { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"] },
    );
  } catch (error) {
    const stdout = (error as { stdout?: unknown })?.stdout;
    raw = typeof stdout === "string" ? stdout : "";
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
  const hits: OsvPackageHit[] = [];
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
      hits.push({
        name: info.name ?? "unknown",
        version: info.version ?? "unknown",
        ecosystem: info.ecosystem,
        vulns,
      });
    }
  }
  return hits;
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
