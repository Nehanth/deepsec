import fs from "node:fs";
import path from "node:path";
import { type AgentProgress, runSetupTask } from "@deepsec/processor";
import {
  compileDeclarativeMatchers,
  type DeclarativeMatcherPlugin,
  type DeclarativeMatcherSpec,
} from "@deepsec/scanner";
import { atomicWriteFileSync } from "../atomic-file.js";
import type { CoverageReport, ExpandedSurfaceInventoryItem } from "./coverage.js";

export interface ProposeMatchersOptions {
  projectRoot: string;
  agentType: string;
  agentConfig: Record<string, unknown>;
  inventory: ExpandedSurfaceInventoryItem[];
  coverage: CoverageReport;
  existingSlugs: string[];
  /** Project threat model (INFO.md). Lets matchers target reachable dependency advisories. */
  threatModel?: string;
  /** Known-vulnerable dependency count; when > 0, matchers are proposed even if every surface is already covered. */
  dependencyCveCount?: number;
  signal?: AbortSignal;
  onProgress?: (progress: AgentProgress) => void;
  runTask?: typeof runSetupTask;
}

/** A proposed matcher that failed validation and was dropped. */
export interface RejectedMatcher {
  slug: string;
  reason: string;
}

function extractArray(raw: string): unknown[] {
  const fenced = raw.match(/```(?:json)?\s*([\s\S]*?)```/i)?.[1];
  const text = (fenced ?? raw).trim();
  const parsed = JSON.parse(text.slice(text.indexOf("["), text.lastIndexOf("]") + 1));
  if (!Array.isArray(parsed)) throw new Error("Matcher proposal must be a JSON array");
  return parsed;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Compile each proposed matcher on its own, so one invalid matcher (an example
 * its pattern doesn't match, an unsupported regex) drops only itself instead of
 * failing the whole proposal.
 */
function compileEach(
  items: unknown[],
  existingSlugs: Iterable<string>,
): { plugins: DeclarativeMatcherPlugin[]; rejected: RejectedMatcher[] } {
  const slugs = new Set(existingSlugs);
  const plugins: DeclarativeMatcherPlugin[] = [];
  const rejected: RejectedMatcher[] = [];
  items.forEach((item, index) => {
    try {
      const [plugin] = compileDeclarativeMatchers([item], { existingSlugs: slugs });
      slugs.add(plugin.slug);
      plugins.push(plugin);
    } catch (error) {
      const slug = (item as { slug?: unknown } | null)?.slug;
      rejected.push({
        slug: typeof slug === "string" && slug ? slug : `#${index}`,
        reason: errorMessage(error),
      });
    }
  });
  return { plugins, rejected };
}

/** Parse and compile one agent response; an unparseable response rejects as a whole. */
function compileResponse(
  raw: string,
  existingSlugs: Iterable<string>,
): { plugins: DeclarativeMatcherPlugin[]; rejected: RejectedMatcher[] } {
  let items: unknown[];
  try {
    items = extractArray(raw);
  } catch (error) {
    return { plugins: [], rejected: [{ slug: "(proposal)", reason: errorMessage(error) }] };
  }
  return compileEach(items, existingSlugs);
}

export async function proposeGeneratedMatchers(options: ProposeMatchersOptions): Promise<{
  specs: DeclarativeMatcherSpec[];
  plugins: DeclarativeMatcherPlugin[];
  /** Proposed matchers dropped at validation; the rest of the proposal was kept. */
  rejected?: RejectedMatcher[];
}> {
  const uncovered = options.coverage.surfaces.filter((surface) => !surface.passed);
  const hasDepCves = (options.dependencyCveCount ?? 0) > 0;
  if (uncovered.length === 0 && options.coverage.languageWarnings.length === 0 && !hasDepCves) {
    return { specs: [], plugins: [], rejected: [] };
  }
  // When the project has known-vulnerable dependencies, point the agent at the
  // reachable advisories from the threat model so the vulnerable call sites get a
  // matcher — otherwise matcher generation only ever fills surface-coverage gaps,
  // and a dependency CVE whose code isn't an uncovered surface never gets flagged.
  const advisoryBlock =
    hasDepCves && options.threatModel?.trim()
      ? `

This project has known-vulnerable dependencies and/or advisories for the package itself from newer releases. In addition to the surface gaps above, propose matchers that flag the *reachable* dependency advisories and the package advisories graded LIKELY AFFECTED or CHECK in the threat model below. Anchor each to the specific vulnerable call site or condition (for example a form-parsing call made with no size/field limit), so those spots become scan candidates. Skip advisories the threat model marks not-reachable or LIKELY NOT PRESENT. Set closesSurfaceIds to the surface(s) from the inventory where the vulnerable call occurs (the matcher schema requires at least one); use the closest ingress surface that reaches the call.

Threat model (INFO.md):
${options.threatModel.trim()}`
      : "";
  const prompt = `Design narrow, data-only deepsec coverage matchers for the repository. Read files only; do not execute code, use the network, read env files, or install packages.

Return ONLY a JSON array. Each item must have exactly: version:1, slug (kebab-case), description, noiseTier (precise|normal|noisy), filePatterns, optional requires {tech and/or sentinelFiles}, patterns [{source, optional flags i|m|im, label}], optional excludeFilePatterns, examples (each must match a pattern), and closesSurfaceIds.

Only close a surface when the matcher targets its concrete framework/registration primitive. Prefer anchored, framework-specific patterns. Never emit a broad catch-all. Existing slugs must not be reused: ${JSON.stringify(options.existingSlugs)}.

Inventory: ${JSON.stringify(options.inventory)}
Coverage gaps: ${JSON.stringify({ surfaces: uncovered, languages: options.coverage.languageWarnings })}${advisoryBlock}`;
  const runTask = options.runTask ?? runSetupTask;
  let raw = await runTask({
    agentType: options.agentType,
    projectRoot: options.projectRoot,
    prompt,
    config: options.agentConfig,
    signal: options.signal,
    onProgress: options.onProgress,
  });
  const first = compileResponse(raw, options.existingSlugs);
  let plugins = first.plugins;
  let rejected = first.rejected;
  if (rejected.length > 0) {
    // Keep what validated; ask once for replacements of only the rejected matchers.
    const accepted = plugins.map((plugin) => plugin.slug);
    raw = await runTask({
      agentType: options.agentType,
      projectRoot: options.projectRoot,
      prompt: `${prompt}\n\nThese proposed matchers failed validation and were dropped:\n${rejected
        .map((r) => `- ${r.slug}: ${r.reason}`)
        .join(
          "\n",
        )}\nThese were accepted and must not be repeated: ${JSON.stringify(accepted)}. Return a JSON array containing only corrected replacements for the dropped matchers (or [] if none can be fixed).`,
      config: options.agentConfig,
      signal: options.signal,
      onProgress: options.onProgress,
    });
    const retry = compileResponse(raw, [...options.existingSlugs, ...accepted]);
    plugins = [...plugins, ...retry.plugins];
    // Every spec that was dropped, from either round (a replacement may have taken its place).
    rejected = [...rejected, ...retry.rejected];
  }
  if (plugins.length === 0 && rejected.length > 0) {
    throw new Error(
      `No proposed matcher passed validation: ${rejected
        .map((r) => `${r.slug}: ${r.reason}`)
        .join("; ")}`,
    );
  }
  return { specs: plugins.map((plugin) => plugin.declarativeSpec), plugins, rejected };
}

export function writeGeneratedMatchers(
  workspaceDir: string,
  specs: DeclarativeMatcherSpec[],
): string {
  const file = path.join(workspaceDir, "generated-matchers.ts");
  const content = `import { compileDeclarativeMatchers, type DeepsecPlugin } from "deepsec/config";\n\nconst specs = ${JSON.stringify(specs, null, 2)};\n\nexport const generatedMatchersPlugin: DeepsecPlugin = {\n  name: "deepsec-generated-matchers",\n  matchers: compileDeclarativeMatchers(specs),\n};\n`;
  atomicWriteFileSync(file, content);
  return file;
}

/** Read the specs from Deepsec's generated file so resumed setup only appends. */
export function readGeneratedMatchers(workspaceDir: string): DeclarativeMatcherPlugin[] {
  const file = path.join(workspaceDir, "generated-matchers.ts");
  if (!fs.existsSync(file)) return [];
  const source = fs.readFileSync(file, "utf8");
  const serialized = source.match(/const specs\s*=\s*(\[[\s\S]*?\]);\s*\n\s*export const/)?.[1];
  if (!serialized) return [];
  return compileDeclarativeMatchers(JSON.parse(serialized));
}
