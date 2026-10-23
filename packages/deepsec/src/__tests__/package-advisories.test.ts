import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { mergeInfoWithOsvContext, PACKAGE_CONTEXT_HEADING } from "../setup/osv-enrich.js";
import {
  buildPackageAdvisoryContext,
  classifyAdvisories,
  compareVersions,
  detectPackageIdentity,
  PACKAGE_ADVISORY_HEADING,
  runPackageAdvisories,
} from "../setup/package-advisories.js";

function tmpProject(files: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pkgadv-"));
  for (const [rel, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), text);
  }
  return root;
}

const range = (introduced: string, fixed?: string) => ({
  ranges: [{ type: "ECOSYSTEM", events: [{ introduced }, ...(fixed ? [{ fixed }] : [])] }],
});

describe("detectPackageIdentity", () => {
  it("reads name and version from PKG-INFO", () => {
    const root = tmpProject({
      "source/PKG-INFO": "Metadata-Version: 2.1\nName: soupsieve\nVersion: 2.7\n",
    });
    expect(detectPackageIdentity(root)).toMatchObject({
      name: "soupsieve",
      version: "2.7",
      ecosystem: "PyPI",
    });
  });

  it("falls back to a static [project] table in pyproject.toml", () => {
    const root = tmpProject({
      "pyproject.toml": '[project]\nname = "acme"\nversion = "1.4.0"\n\n[tool.x]\nname = "nope"\n',
    });
    expect(detectPackageIdentity(root)).toMatchObject({ name: "acme", version: "1.4.0" });
  });

  it("reads Maven coordinates, ignoring the <parent> block", () => {
    const root = tmpProject({
      "pom.xml":
        "<project><parent><groupId>org.parent</groupId><artifactId>p</artifactId><version>9</version></parent>" +
        "<groupId>org.acme</groupId><artifactId>widget</artifactId><version>2.1</version></project>",
    });
    expect(detectPackageIdentity(root)).toMatchObject({
      name: "org.acme:widget",
      version: "2.1",
      ecosystem: "Maven",
    });
  });

  it("returns undefined when there's no static metadata (e.g. a dynamic version)", () => {
    const root = tmpProject({
      "pyproject.toml": '[project]\nname = "acme"\ndynamic = ["version"]\n',
    });
    expect(detectPackageIdentity(root)).toBeUndefined();
  });
});

describe("compareVersions", () => {
  it("compares numeric parts, not strings", () => {
    expect(compareVersions("1.10", "1.9")).toBe(1);
    expect(compareVersions("2.7", "2.7.0")).toBe(0);
    expect(compareVersions("0.142.0", "0.159.1")).toBe(-1);
  });
  it("refuses to guess on pre-releases and git refs", () => {
    expect(compareVersions("1.0rc1", "1.0")).toBeUndefined();
    expect(compareVersions("fa7e3c99", "1.0")).toBeUndefined();
  });
});

describe("classifyAdvisories", () => {
  const all = [
    {
      id: "GHSA-in",
      aliases: ["CVE-1", "PYSEC-1"],
      summary: "in range",
      affected: [range("0", "2.8.4")],
    },
    {
      id: "PYSEC-1",
      aliases: ["CVE-1", "GHSA-in"],
      summary: "duplicate",
      affected: [range("0", "2.8.4")],
    },
    { id: "GHSA-newer", summary: "newer only", affected: [range("3.0", "3.1")] },
    { id: "GHSA-old", summary: "fixed long ago", affected: [range("0", "1.0")] },
  ];

  it("keeps in-range and newer-only advisories, drops ones fixed before this version, dedupes aliases", () => {
    const out = classifyAdvisories(all, new Set(["GHSA-in"]), "2.7");
    expect(out.map((a) => [a.id, a.kind])).toEqual([
      ["GHSA-in", "in-range"],
      ["GHSA-newer", "newer-only"],
    ]);
    expect(out[0].fixed).toEqual(["2.8.4"]);
    expect(out[1].introduced).toBe("3.0");
  });

  it("matches OSV's in-range answer by alias too", () => {
    const out = classifyAdvisories(all, new Set(["CVE-1"]), "2.7");
    expect(out.find((a) => a.id === "GHSA-in")?.kind).toBe("in-range");
  });
});

describe("buildPackageAdvisoryContext", () => {
  const identity = { name: "acme", version: "1.4", ecosystem: "PyPI" as const, source: "PKG-INFO" };

  it("is empty when nothing applies", () => {
    expect(buildPackageAdvisoryContext(identity, [])).toBe("");
  });

  it("lists both kinds and requires a graded subsection per advisory", () => {
    const ctx = buildPackageAdvisoryContext(identity, [
      {
        id: "GHSA-a",
        aliases: ["CVE-1"],
        fixed: ["2.0"],
        kind: "in-range",
        summary: "path traversal",
      },
      {
        id: "GHSA-b",
        aliases: [],
        fixed: [],
        kind: "newer-only",
        introduced: "3.0",
        summary: "template eval",
      },
    ]);
    expect(ctx).toContain(PACKAGE_CONTEXT_HEADING);
    expect(ctx).toContain("`acme@1.4`");
    expect(ctx).toContain("GHSA-a (CVE-1) — fixed in 2.0: path traversal");
    expect(ctx).toContain("GHSA-b — recorded from 3.0: template eval");
    expect(ctx).toContain(`${PACKAGE_ADVISORY_HEADING} (required)`);
    expect(ctx).toMatch(/LIKELY AFFECTED\|CHECK\|LIKELY NOT PRESENT/);
  });
});

describe("runPackageAdvisories", () => {
  const project = () => tmpProject({ "PKG-INFO": "Name: acme\nVersion: 1.4\n" });

  it("queries OSV twice (all advisories + this version) and persists the result", async () => {
    const calls: unknown[] = [];
    const fake = (async (_url: string, init: { body: string }) => {
      const body = JSON.parse(init.body);
      calls.push(body);
      const vulns = body.version
        ? [{ id: "GHSA-a", affected: [range("0", "2.0")] }]
        : [
            { id: "GHSA-a", affected: [range("0", "2.0")] },
            { id: "GHSA-old", affected: [range("0", "1.0")] },
          ];
      return new Response(JSON.stringify({ vulns }), { status: 200 });
    }) as unknown as typeof fetch;
    const data = fs.mkdtempSync(path.join(os.tmpdir(), "pkgadv-data-"));
    const r = await runPackageAdvisories(project(), data, fake);
    expect(calls).toHaveLength(2);
    expect(r.advisories.map((a) => a.id)).toEqual(["GHSA-a"]);
    expect(r.context).toContain("GHSA-a");
    const saved = JSON.parse(
      fs.readFileSync(path.join(data, "setup", "package-advisories.json"), "utf8"),
    );
    expect(saved.identity.name).toBe("acme");
  });

  it("degrades to no context on an OSV failure without writing a clean result", async () => {
    const failing = (async () => new Response("down", { status: 503 })) as unknown as typeof fetch;
    const data = fs.mkdtempSync(path.join(os.tmpdir(), "pkgadv-data-"));
    const r = await runPackageAdvisories(project(), data, failing);
    expect(r.context).toBe("");
    expect(fs.existsSync(path.join(data, "setup", "package-advisories.json"))).toBe(false);
  });
});

describe("mergeInfoWithOsvContext", () => {
  it("also strips the package-advisory prompt context from a preserved INFO.md", () => {
    const info = `# app\n\n## Threat model\nCurated.\n\n${PACKAGE_CONTEXT_HEADING}\n\n- GHSA-a — fixed in 2.0\n\n## Known false-positives\nNone.\n`;
    const out = mergeInfoWithOsvContext(info, "");
    expect(out).not.toContain(PACKAGE_CONTEXT_HEADING);
    expect(out).toContain("## Known false-positives\nNone.");
    expect(out).toContain("Curated.");
  });
});
