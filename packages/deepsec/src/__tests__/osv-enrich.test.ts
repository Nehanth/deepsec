import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildContext, findManifest, findManifests, parseOsv } from "../setup/osv-enrich.js";

// osv-scanner's JSON groups packages under results[].packages[], each result
// tagged with a source lockfile path, each package carrying vulnerabilities[]
// of {id, summary}.
const SAMPLE = JSON.stringify({
  results: [
    {
      source: { path: "requirements.txt", type: "lockfile" },
      packages: [
        {
          package: { name: "idna", version: "2.8", ecosystem: "PyPI" },
          vulnerabilities: [
            { id: "PYSEC-2024-60", summary: "idna ReDoS on long domain labels" },
            { id: "GHSA-65pc-fj4g-8rjx", details: "Denial of service via idna.encode()" },
          ],
        },
        {
          // clean dependency: no vulnerabilities, must be dropped
          package: { name: "click", version: "8.1.7", ecosystem: "PyPI" },
          vulnerabilities: [],
        },
      ],
    },
    {
      // deepsec's own workspace deps — vendored path, must be dropped entirely
      source: { path: ".deepsec/node_modules/.package-lock.json", type: "lockfile" },
      packages: [
        {
          package: { name: "undici", version: "8.5.0", ecosystem: "npm" },
          vulnerabilities: [{ id: "GHSA-2gqq-gqf2-x968", summary: "unrelated node dep" }],
        },
      ],
    },
  ],
});

describe("parseOsv", () => {
  it("extracts vulnerable packages with advisory summaries", () => {
    const hits = parseOsv(SAMPLE);
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ name: "idna", version: "2.8", ecosystem: "PyPI" });
    expect(hits[0].vulns).toEqual([
      { id: "PYSEC-2024-60", summary: "idna ReDoS on long domain labels" },
      { id: "GHSA-65pc-fj4g-8rjx", summary: "Denial of service via idna.encode()" },
    ]);
  });

  it("drops vendored sources (.deepsec / node_modules)", () => {
    const names = parseOsv(SAMPLE).map((h) => h.name);
    expect(names).not.toContain("undici");
  });

  it("returns nothing for empty or non-JSON output (osv missing / no sources)", () => {
    expect(parseOsv("")).toEqual([]);
    expect(parseOsv("No package sources found")).toEqual([]);
  });
});

describe("findManifest", () => {
  it("finds a nested pyproject.toml but skips vendored and hidden trees", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-manifest-"));
    try {
      // A decoy inside a vendored tree must not be picked.
      fs.mkdirSync(path.join(root, "node_modules", "dep"), { recursive: true });
      fs.writeFileSync(path.join(root, "node_modules", "dep", "pyproject.toml"), "");
      fs.mkdirSync(path.join(root, "src", "pkg"), { recursive: true });
      const real = path.join(root, "src", "pkg", "pyproject.toml");
      fs.writeFileSync(real, "[project]\nname='x'\n");

      expect(findManifest(root)).toBe(real);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it("returns undefined when there is no manifest", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-manifest-"));
    try {
      expect(findManifest(root)).toBeUndefined();
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("parseOsv field sanitization (prompt-injection defense)", () => {
  it("collapses newlines/markdown in attacker-controlled name and version", () => {
    const raw = JSON.stringify({
      results: [
        {
          source: { path: "requirements.txt" },
          packages: [
            {
              package: {
                name: "evil\n## Injected heading\n- bullet",
                version: "1.0\n\nmore",
                ecosystem: "PyPI",
              },
              vulnerabilities: [{ id: "CVE-1", summary: "x" }],
            },
          ],
        },
      ],
    });
    const hits = parseOsv(raw);
    expect(hits).toHaveLength(1);
    expect(hits[0].name).not.toContain("\n");
    expect(hits[0].version).not.toContain("\n");
    // and the rendered prompt block carries no injected newlines from those fields
    const ctx = buildContext(hits);
    expect(ctx).toContain("Injected heading"); // present, but inline — not a real heading
    expect(ctx).not.toMatch(/\n##? Injected heading/);
  });
});

describe("findManifests (monorepo)", () => {
  it("returns every pyproject.toml, not just the first", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-multi-"));
    try {
      fs.mkdirSync(path.join(root, "pkg-a"), { recursive: true });
      fs.mkdirSync(path.join(root, "pkg-b"), { recursive: true });
      fs.writeFileSync(path.join(root, "pkg-a", "pyproject.toml"), "");
      fs.writeFileSync(path.join(root, "pkg-b", "pyproject.toml"), "");
      const found = findManifests(root);
      expect(found).toHaveLength(2);
      expect(findManifest(root)).toBe(found[0]); // single-use helper returns the first
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("buildContext", () => {
  it("is empty when there are no vulnerable dependencies", () => {
    expect(buildContext([])).toBe("");
  });

  it("lists each advisory id with its summary so the ids are self-explanatory", () => {
    const ctx = buildContext([
      { name: "idna", version: "2.8", vulns: [{ id: "PYSEC-2024-60", summary: "ReDoS" }] },
    ]);
    expect(ctx).toContain("`idna@2.8`");
    expect(ctx).toContain("PYSEC-2024-60: ReDoS");
  });
});
