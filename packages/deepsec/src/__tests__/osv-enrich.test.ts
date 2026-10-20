import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildContext, findManifest, findPom, parseOsv } from "../setup/osv-enrich.js";

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

  it("dedupes a package seen from two sources, merging unique advisories", () => {
    // Same Maven dep from osv's pom.xml parse AND the syft SBOM.
    const raw = JSON.stringify({
      results: [
        {
          source: { path: "pom.xml" },
          packages: [
            {
              package: { name: "log4j-core", version: "2.14.1", ecosystem: "Maven" },
              vulnerabilities: [{ id: "GHSA-jfh8-c2jp-5v3q" }],
            },
          ],
        },
        {
          source: { path: "/tmp/x/deps.cdx.json" },
          packages: [
            {
              package: { name: "log4j-core", version: "2.14.1", ecosystem: "Maven" },
              vulnerabilities: [{ id: "GHSA-jfh8-c2jp-5v3q" }, { id: "GHSA-7rjr-3q55-vv33" }],
            },
          ],
        },
      ],
    });
    const hits = parseOsv(raw);
    expect(hits).toHaveLength(1);
    expect(hits[0].vulns.map((v) => v.id)).toEqual(["GHSA-jfh8-c2jp-5v3q", "GHSA-7rjr-3q55-vv33"]);
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

describe("findPom", () => {
  it("finds a nested pom.xml but skips vendored trees", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-pom-"));
    try {
      fs.mkdirSync(path.join(root, "vendor", "lib"), { recursive: true });
      fs.writeFileSync(path.join(root, "vendor", "lib", "pom.xml"), "");
      fs.mkdirSync(path.join(root, "server"), { recursive: true });
      const real = path.join(root, "server", "pom.xml");
      fs.writeFileSync(real, "<project></project>\n");

      expect(findPom(root)).toBe(real);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it("returns undefined when there is no pom", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-pom-"));
    try {
      expect(findPom(root)).toBeUndefined();
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
