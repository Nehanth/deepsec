import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildClaudeEnv } from "../agents/claude-agent-sdk.js";

// Claude-on-Vertex routing: the claude backend reaches Vertex via Claude Code's
// own env vars (GCP ADC/service account). buildClaudeEnv must forward those to the
// spawned child, while the allowlist still drops everything else (e.g. GITHUB_TOKEN).

const KEYS = [
  "CLAUDE_CODE_USE_VERTEX",
  "ANTHROPIC_VERTEX_PROJECT_ID",
  "GOOGLE_CLOUD_PROJECT",
  "GCLOUD_PROJECT",
  "CLOUD_ML_REGION",
  "GOOGLE_APPLICATION_CREDENTIALS",
  "CLOUDSDK_CONFIG",
  "CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS",
  "VERTEX_REGION_CLAUDE_SONNET_4_6",
  "GITHUB_TOKEN",
] as const;
const saved: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const k of KEYS) saved[k] = process.env[k];
  for (const k of KEYS) delete process.env[k];
});
afterEach(() => {
  for (const k of KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});

describe("buildClaudeEnv — Vertex routing", () => {
  it("forwards the Vertex credential-routing vars to the child", () => {
    process.env.CLAUDE_CODE_USE_VERTEX = "1";
    process.env.ANTHROPIC_VERTEX_PROJECT_ID = "my-project";
    process.env.CLOUD_ML_REGION = "us-east5";
    process.env.GOOGLE_APPLICATION_CREDENTIALS = "/path/sa.json";
    process.env.CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS = "1";
    const env = buildClaudeEnv();
    expect(env.CLAUDE_CODE_USE_VERTEX).toBe("1");
    expect(env.ANTHROPIC_VERTEX_PROJECT_ID).toBe("my-project");
    expect(env.CLOUD_ML_REGION).toBe("us-east5");
    expect(env.GOOGLE_APPLICATION_CREDENTIALS).toBe("/path/sa.json");
    // Required on Vertex — the SDK otherwise sends beta headers Vertex rejects.
    expect(env.CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS).toBe("1");
  });

  it("forwards dynamic per-model region overrides (VERTEX_REGION_CLAUDE_*)", () => {
    process.env.VERTEX_REGION_CLAUDE_SONNET_4_6 = "europe-west1";
    expect(buildClaudeEnv().VERTEX_REGION_CLAUDE_SONNET_4_6).toBe("europe-west1");
  });

  it("still drops non-allowlisted secrets (allowlist stays tight)", () => {
    process.env.CLAUDE_CODE_USE_VERTEX = "1";
    process.env.GITHUB_TOKEN = "ghp_should_not_leak";
    expect(buildClaudeEnv().GITHUB_TOKEN).toBeUndefined();
  });
});
