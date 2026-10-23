import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DeclarativeMatcherSpec } from "@deepsec/scanner";
import { describe, expect, it } from "vitest";
import type { CoverageReport } from "../setup/coverage.js";
import {
  type ProposeMatchersOptions,
  proposeGeneratedMatchers,
  readGeneratedMatchers,
  writeGeneratedMatchers,
} from "../setup/generated-matchers.js";

function spec(slug: string): DeclarativeMatcherSpec {
  return {
    version: 1,
    slug,
    description: `${slug} matcher`,
    noiseTier: "precise",
    filePatterns: ["**/*.ts"],
    patterns: [{ source: "export", label: "export" }],
    examples: ["export const value = 1"],
    closesSurfaceIds: ["api"],
  };
}

/** Coverage where every surface is already covered (no gaps, no warnings). */
function fullyCovered(): CoverageReport {
  return {
    policyVersion: 1,
    passed: true,
    sourceFileCount: 1,
    candidateFileCount: 1,
    surfaces: [],
    languageWarnings: [],
    explosionWarnings: [],
    reasons: [],
  };
}

function baseOptions(overrides: Partial<ProposeMatchersOptions>): ProposeMatchersOptions {
  return {
    projectRoot: "/tmp/does-not-matter",
    agentType: "claude",
    agentConfig: {},
    inventory: [],
    coverage: fullyCovered(),
    existingSlugs: [],
    ...overrides,
  };
}

describe("proposeGeneratedMatchers dependency-CVE steering", () => {
  it("returns nothing when there are no gaps and no vulnerable dependencies", async () => {
    let called = false;
    const runTask = (async () => {
      called = true;
      return "[]";
    }) as ProposeMatchersOptions["runTask"];

    const result = await proposeGeneratedMatchers(baseOptions({ runTask }));
    expect(result.plugins).toHaveLength(0);
    expect(called).toBe(false); // early-returned without calling the agent
  });

  it("proposes matchers for vulnerable deps even when every surface is covered", async () => {
    let prompt = "";
    const runTask = (async (params: { prompt: string }) => {
      prompt = params.prompt;
      return JSON.stringify([
        {
          version: 1,
          slug: "py-form-no-limits",
          description: "form parsed without size/field limits",
          noiseTier: "precise",
          filePatterns: ["**/*.py"],
          patterns: [{ source: "request\\.form\\(\\)", label: "form" }],
          examples: ["await request.form()"],
          closesSurfaceIds: ["api"],
        },
      ]);
    }) as ProposeMatchersOptions["runTask"];

    const result = await proposeGeneratedMatchers(
      baseOptions({
        runTask,
        dependencyCveCount: 3,
        threatModel:
          "## Threat model\nStarlette multipart DoS reachable via request.form() with no max_fields.",
      }),
    );

    expect(result.plugins.map((p) => p.slug)).toContain("py-form-no-limits");
    // the threat model was handed to the agent so it can target the advisory
    expect(prompt).toContain("known-vulnerable dependencies");
    expect(prompt).toContain("request.form()");
  });
});

describe("proposeGeneratedMatchers partial validation", () => {
  // Shapes the setup agent really produced: an example its own pattern doesn't
  // match, and a regex with stacked wildcards the safety check refuses.
  const badExample = { ...spec("bad-example"), examples: ["no keyword here"] };
  const badWildcard = {
    ...spec("bad-wildcard"),
    patterns: [{ source: "export.*const.*value", label: "x" }],
    examples: ["export const value = 1"],
  };

  /** Agent stub that returns each response in turn and records every prompt. */
  function agent(...responses: unknown[][]) {
    const prompts: string[] = [];
    const runTask = (async (params: { prompt: string }) => {
      prompts.push(params.prompt);
      return JSON.stringify(responses[prompts.length - 1] ?? []);
    }) as ProposeMatchersOptions["runTask"];
    return { runTask, prompts };
  }

  it("keeps the valid matchers when one fails, instead of rejecting the whole proposal", async () => {
    const { runTask, prompts } = agent([spec("good-route"), badExample], []);
    const result = await proposeGeneratedMatchers(baseOptions({ runTask, dependencyCveCount: 1 }));

    expect(result.plugins.map((p) => p.slug)).toEqual(["good-route"]);
    expect(result.rejected?.map((r) => r.slug)).toEqual(["bad-example"]);
    expect(result.rejected?.[0].reason).toMatch(/must be matched by at least one declared pattern/);
    // one retry, asking only for replacements and naming what was already accepted
    expect(prompts).toHaveLength(2);
    expect(prompts[1]).toContain("bad-example");
    expect(prompts[1]).toContain('["good-route"]');
  });

  it("adds a corrected replacement from the retry alongside the kept matchers", async () => {
    const { runTask } = agent([spec("good-route"), badWildcard], [spec("fixed-route")]);
    const result = await proposeGeneratedMatchers(baseOptions({ runTask, dependencyCveCount: 1 }));

    expect(result.plugins.map((p) => p.slug)).toEqual(["good-route", "fixed-route"]);
    expect(result.rejected?.[0]).toMatchObject({ slug: "bad-wildcard" });
    expect(result.rejected?.[0].reason).toMatch(/multiple wildcard repetitions/);
  });

  it("does not retry when every proposed matcher is valid", async () => {
    const { runTask, prompts } = agent([spec("good-route"), spec("other-route")]);
    const result = await proposeGeneratedMatchers(baseOptions({ runTask, dependencyCveCount: 1 }));

    expect(result.plugins).toHaveLength(2);
    expect(result.rejected).toEqual([]);
    expect(prompts).toHaveLength(1);
  });

  it("still fails when no proposed matcher validates in either round", async () => {
    const { runTask } = agent([badExample], [badWildcard]);
    await expect(
      proposeGeneratedMatchers(baseOptions({ runTask, dependencyCveCount: 1 })),
    ).rejects.toThrow(/No proposed matcher passed validation/);
  });

  it("drops a duplicate slug from the retry rather than failing", async () => {
    const { runTask } = agent([spec("good-route"), badExample], [spec("good-route")]);
    const result = await proposeGeneratedMatchers(baseOptions({ runTask, dependencyCveCount: 1 }));

    expect(result.plugins.map((p) => p.slug)).toEqual(["good-route"]);
    expect(result.rejected?.map((r) => r.slug)).toEqual(["bad-example", "good-route"]);
  });
});

describe("proposeGeneratedMatchers shape normalization", () => {
  async function propose(items: unknown[]) {
    const runTask = (async () => JSON.stringify(items)) as ProposeMatchersOptions["runTask"];
    return proposeGeneratedMatchers(baseOptions({ runTask, dependencyCveCount: 1 }));
  }

  it('accepts a single string where a list is expected ("tech": "java")', async () => {
    const result = await propose([
      { ...spec("ws-subscribe"), requires: { tech: "java", sentinelFiles: "**/pom.xml" } },
    ]);

    expect(result.rejected).toEqual([]);
    expect(result.plugins.map((p) => p.slug)).toEqual(["ws-subscribe"]);
    expect(result.specs[0].requires).toEqual({ tech: ["java"], sentinelFiles: ["**/pom.xml"] });
  });

  it("wraps single-string top-level list fields", async () => {
    const result = await propose([
      {
        ...spec("one-liner"),
        filePatterns: "**/*.ts",
        examples: "export const value = 1",
        closesSurfaceIds: "api",
      },
    ]);

    expect(result.rejected).toEqual([]);
    expect(result.specs[0]).toMatchObject({
      filePatterns: ["**/*.ts"],
      examples: ["export const value = 1"],
      closesSurfaceIds: ["api"],
    });
  });

  it("treats an empty regex flag as no flags", async () => {
    const result = await propose([
      { ...spec("no-flags"), patterns: [{ source: "export", flags: "", label: "export" }] },
    ]);

    expect(result.rejected).toEqual([]);
    expect(result.specs[0].patterns[0]).not.toHaveProperty("flags");
  });

  it("still rejects a genuinely invalid matcher after normalizing", async () => {
    const result = await propose([
      spec("good-route"),
      { ...spec("bad-example"), requires: { tech: "java" }, examples: ["no keyword here"] },
    ]);

    expect(result.plugins.map((p) => p.slug)).toEqual(["good-route"]);
    expect(result.rejected?.[0]).toMatchObject({ slug: "bad-example" });
  });

  it("tells the agent that list fields are arrays", async () => {
    let prompt = "";
    const runTask = (async (params: { prompt: string }) => {
      prompt = params.prompt;
      return "[]";
    }) as ProposeMatchersOptions["runTask"];
    await proposeGeneratedMatchers(baseOptions({ runTask, dependencyCveCount: 1 }));

    expect(prompt).toContain('"tech": ["java"]');
    expect(prompt).toContain("tech: array of strings");
  });
});

describe("generated matcher persistence", () => {
  it("reads previous specs so a resumed generation pass can append", () => {
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-matchers-"));
    writeGeneratedMatchers(workspace, [spec("existing-route")]);
    const existing = readGeneratedMatchers(workspace);
    writeGeneratedMatchers(workspace, [
      ...existing.map((matcher) => matcher.declarativeSpec),
      spec("new-route"),
    ]);

    expect(readGeneratedMatchers(workspace).map((matcher) => matcher.slug)).toEqual([
      "existing-route",
      "new-route",
    ]);
  });
});
