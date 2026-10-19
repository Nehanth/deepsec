import { describe, expect, it } from "vitest";
import { buildContext, parseOsv } from "../setup/osv-enrich.js";

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
