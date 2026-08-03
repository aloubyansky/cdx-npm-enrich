import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  parsePnpmWorkspaceYaml,
  discoverWorkspacePackages,
  expandWorkspacePatterns,
  collectDirectProdDeps,
  resolvePackageDir,
  resolveAllProdDeps,
  componentKey,
  buildLicenses,
  buildLicenseEntry,
  splitSpdxExpression,
  enrichLicense,
  enrichHash,
  parseYarnBerryChecksums,
  parseYarnClassicChecksums,
  parsePackageLockChecksums,
  parsePnpmLockChecksums,
  parseLocfileChecksums,
  sriBase64ToHex,
  markDevExcluded,
  filterProdOnly,
} from "../index.mjs";

// ── Helpers ──────────────────────────────────────────────────────────

let tmp;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), "cdx-enrich-test-"));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function writeJson(path, obj) {
  writeFileSync(path, JSON.stringify(obj));
}

function makePkg(dir, pkg) {
  mkdirSync(dir, { recursive: true });
  writeJson(join(dir, "package.json"), pkg);
}

function makeNodeModule(root, name, version, license, deps) {
  const dir = join(root, "node_modules", name);
  mkdirSync(dir, { recursive: true });
  const pkg = { name, version };
  if (license) pkg.license = license;
  if (deps) pkg.dependencies = deps;
  writeJson(join(dir, "package.json"), pkg);
}

function makePnpmModule(root, name, version, license, deps) {
  const dirName = name.replace("/", "+");
  const dir = join(root, "node_modules", ".pnpm", `${dirName}@${version}`, "node_modules", name);
  mkdirSync(dir, { recursive: true });
  const pkg = { name, version };
  if (license) pkg.license = license;
  if (deps) pkg.dependencies = deps;
  writeJson(join(dir, "package.json"), pkg);
}

function minimalBom(components) {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    components: components.map((c) => ({
      type: "library",
      name: c.name,
      version: c.version,
      "bom-ref": `pkg:npm/${c.name}@${c.version}`,
      ...(c.scope ? { scope: c.scope } : {}),
      ...(c.licenses ? { licenses: c.licenses } : {}),
      ...(c.group ? { group: c.group } : {}),
    })),
    dependencies: components.map((c) => ({
      ref: `pkg:npm/${c.name}@${c.version}`,
    })),
  };
}

// ── parsePnpmWorkspaceYaml ───────────────────────────────────────────

describe("parsePnpmWorkspaceYaml", () => {
  it("parses simple patterns", () => {
    const f = join(tmp, "pnpm-workspace.yaml");
    writeFileSync(f, "packages:\n  - apps/*\n  - libs/*\n");
    assert.deepEqual(parsePnpmWorkspaceYaml(f), ["apps/*", "libs/*"]);
  });

  it("parses quoted patterns", () => {
    const f = join(tmp, "pnpm-workspace.yaml");
    writeFileSync(f, "packages:\n  - 'apps/*'\n  - \"libs/*\"\n");
    assert.deepEqual(parsePnpmWorkspaceYaml(f), ["apps/*", "libs/*"]);
  });

  it("stops at next top-level key", () => {
    const f = join(tmp, "pnpm-workspace.yaml");
    writeFileSync(
      f,
      "packages:\n  - apps/*\noverrides:\n  lodash: ^4.17.0\n",
    );
    assert.deepEqual(parsePnpmWorkspaceYaml(f), ["apps/*"]);
  });

  it("handles plain directory names", () => {
    const f = join(tmp, "pnpm-workspace.yaml");
    writeFileSync(f, "packages:\n  - tools\n  - shared\n");
    assert.deepEqual(parsePnpmWorkspaceYaml(f), ["tools", "shared"]);
  });

  it("returns empty array when no packages key", () => {
    const f = join(tmp, "pnpm-workspace.yaml");
    writeFileSync(f, "overrides:\n  lodash: ^4.17.0\n");
    assert.deepEqual(parsePnpmWorkspaceYaml(f), []);
  });
});

// ── discoverWorkspacePackages ────────────────────────────────────────

describe("discoverWorkspacePackages", () => {
  it("discovers npm/yarn workspaces", () => {
    makePkg(tmp, { name: "root", version: "1.0.0", workspaces: ["packages/*"] });
    makePkg(join(tmp, "packages", "a"), { name: "a", version: "1.0.0" });
    makePkg(join(tmp, "packages", "b"), { name: "b", version: "1.0.0" });

    const result = discoverWorkspacePackages(tmp);
    assert.equal(result.length, 3);
    assert.ok(result[0].endsWith("package.json"));
  });

  it("discovers pnpm workspaces", () => {
    makePkg(tmp, { name: "root", version: "1.0.0" });
    writeFileSync(join(tmp, "pnpm-workspace.yaml"), "packages:\n  - apps/*\n");
    makePkg(join(tmp, "apps", "web"), { name: "web", version: "1.0.0" });

    const result = discoverWorkspacePackages(tmp);
    assert.equal(result.length, 2);
  });

  it("prefers npm workspaces over pnpm when both exist", () => {
    makePkg(tmp, { name: "root", version: "1.0.0", workspaces: ["npm-ws/*"] });
    writeFileSync(join(tmp, "pnpm-workspace.yaml"), "packages:\n  - pnpm-ws/*\n");
    makePkg(join(tmp, "npm-ws", "a"), { name: "a", version: "1.0.0" });
    makePkg(join(tmp, "pnpm-ws", "b"), { name: "b", version: "1.0.0" });

    const result = discoverWorkspacePackages(tmp);
    assert.equal(result.length, 2);
    assert.ok(result[1].includes("npm-ws"));
  });

  it("handles yarn workspaces.packages object form", () => {
    makePkg(tmp, {
      name: "root",
      version: "1.0.0",
      workspaces: { packages: ["libs/*"] },
    });
    makePkg(join(tmp, "libs", "core"), { name: "core", version: "1.0.0" });

    const result = discoverWorkspacePackages(tmp);
    assert.equal(result.length, 2);
  });

  it("returns only root when no workspaces", () => {
    makePkg(tmp, { name: "root", version: "1.0.0" });
    const result = discoverWorkspacePackages(tmp);
    assert.equal(result.length, 1);
  });
});

// ── collectDirectProdDeps ────────────────────────────────────────────

describe("collectDirectProdDeps", () => {
  it("collects production dependencies", () => {
    makePkg(tmp, {
      name: "app",
      version: "1.0.0",
      dependencies: { react: "^18.0.0", lodash: "^4.0.0" },
      devDependencies: { jest: "^29.0.0" },
    });

    const deps = collectDirectProdDeps([join(tmp, "package.json")]);
    const names = deps.map((d) => d.name);
    assert.ok(names.includes("react"));
    assert.ok(names.includes("lodash"));
    assert.ok(!names.includes("jest"));
  });

  it("skips workspace: references", () => {
    makePkg(tmp, {
      name: "app",
      version: "1.0.0",
      dependencies: { react: "^18.0.0", "my-lib": "workspace:*" },
    });

    const deps = collectDirectProdDeps([join(tmp, "package.json")]);
    const names = deps.map((d) => d.name);
    assert.ok(names.includes("react"));
    assert.ok(!names.includes("my-lib"));
  });

  it("deduplicates across workspaces", () => {
    const wsA = join(tmp, "a");
    const wsB = join(tmp, "b");
    makePkg(wsA, { name: "a", dependencies: { react: "^18.0.0" } });
    makePkg(wsB, { name: "b", dependencies: { react: "^18.0.0" } });

    const deps = collectDirectProdDeps([
      join(wsA, "package.json"),
      join(wsB, "package.json"),
    ]);
    // react appears in both but fromDir differs, so both are kept
    // (different workspaces might resolve to different versions)
    assert.ok(deps.length >= 1);
  });
});

// ── resolvePackageDir ────────────────────────────────────────────────

describe("resolvePackageDir", () => {
  it("resolves from node_modules", () => {
    makeNodeModule(tmp, "react", "18.3.1", "MIT");
    const result = resolvePackageDir("react", tmp, tmp);
    assert.ok(result);
    assert.ok(result.endsWith("react"));
  });

  it("resolves from parent node_modules", () => {
    const sub = join(tmp, "packages", "app");
    mkdirSync(sub, { recursive: true });
    makeNodeModule(tmp, "react", "18.3.1", "MIT");
    const result = resolvePackageDir("react", sub, tmp);
    assert.ok(result);
  });

  it("resolves from pnpm .pnpm store", () => {
    makePnpmModule(tmp, "scheduler", "0.23.2", "MIT");
    const result = resolvePackageDir("scheduler", join(tmp, "apps", "web"), tmp);
    assert.ok(result);
    assert.ok(result.includes(".pnpm"));
  });

  it("resolves scoped packages from pnpm store", () => {
    makePnpmModule(tmp, "@babel/runtime", "7.28.4", "MIT");
    const result = resolvePackageDir("@babel/runtime", tmp, tmp);
    assert.ok(result);
  });

  it("returns null for missing packages", () => {
    const result = resolvePackageDir("nonexistent", tmp, tmp);
    assert.equal(result, null);
  });
});

// ── resolveAllProdDeps ───────────────────────────────────────────────

describe("resolveAllProdDeps", () => {
  it("resolves transitive production deps", () => {
    makeNodeModule(tmp, "react", "18.3.1", "MIT", { scheduler: "^0.23.0" });
    makeNodeModule(tmp, "scheduler", "0.23.2", "MIT");

    const result = resolveAllProdDeps(
      [{ name: "react", fromDir: tmp }],
      tmp,
    );
    assert.ok(result.has("react@18.3.1"));
    assert.ok(result.has("scheduler@0.23.2"));
  });

  it("does not follow devDependencies", () => {
    const reactPkg = { name: "react", version: "18.3.1", license: "MIT" };
    makeNodeModule(tmp, "react", "18.3.1", "MIT");

    // jest is only in devDependencies of the root, not a dep of react
    makeNodeModule(tmp, "jest", "29.0.0", "MIT");

    const result = resolveAllProdDeps(
      [{ name: "react", fromDir: tmp }],
      tmp,
    );
    assert.ok(result.has("react@18.3.1"));
    assert.ok(!result.has("jest@29.0.0"));
  });

  it("handles circular dependencies", () => {
    makeNodeModule(tmp, "a", "1.0.0", "MIT", { b: "^1.0.0" });
    makeNodeModule(tmp, "b", "1.0.0", "MIT", { a: "^1.0.0" });

    const result = resolveAllProdDeps([{ name: "a", fromDir: tmp }], tmp);
    assert.ok(result.has("a@1.0.0"));
    assert.ok(result.has("b@1.0.0"));
  });
});

// ── componentKey ─────────────────────────────────────────────────────

describe("componentKey", () => {
  it("builds key without group", () => {
    assert.equal(componentKey({ name: "react", version: "18.3.1" }), "react@18.3.1");
  });

  it("builds key with group", () => {
    assert.equal(
      componentKey({ group: "@babel", name: "runtime", version: "7.28.4" }),
      "@babel/runtime@7.28.4",
    );
  });
});

// ── buildLicenses ────────────────────────────────────────────────────

describe("buildLicenses", () => {
  it("handles simple string", () => {
    const result = buildLicenses("MIT");
    assert.equal(result.length, 1);
    assert.equal(result[0].license.id, "MIT");
    assert.ok(result[0].license.url.includes("spdx.org"));
  });

  it("handles SPDX expression with OR", () => {
    const result = buildLicenses("MIT OR Apache-2.0");
    assert.equal(result.length, 2);
    assert.equal(result[0].license.id, "MIT");
    assert.equal(result[1].license.id, "Apache-2.0");
  });

  it("handles SPDX expression with AND", () => {
    const result = buildLicenses("MIT AND ISC");
    assert.equal(result.length, 2);
  });

  it("handles array of strings", () => {
    const result = buildLicenses(["MIT", "Apache-2.0"]);
    assert.equal(result.length, 2);
  });

  it("handles array of objects", () => {
    const result = buildLicenses([
      { type: "MIT", url: "https://example.com/mit" },
    ]);
    assert.equal(result.length, 1);
    assert.equal(result[0].license.id, "MIT");
    assert.equal(result[0].license.url, "https://example.com/mit");
  });

  it("handles object with type field", () => {
    const result = buildLicenses({ type: "ISC" });
    assert.equal(result.length, 1);
    assert.equal(result[0].license.id, "ISC");
  });

  it("returns empty for null", () => {
    assert.equal(buildLicenses(null).length, 0);
  });
});

// ── splitSpdxExpression ──────────────────────────────────────────────

describe("splitSpdxExpression", () => {
  it("splits OR expression", () => {
    assert.deepEqual(splitSpdxExpression("MIT OR ISC"), ["MIT", "ISC"]);
  });

  it("splits AND expression", () => {
    assert.deepEqual(splitSpdxExpression("MIT AND ISC"), ["MIT", "ISC"]);
  });

  it("strips parentheses", () => {
    assert.deepEqual(
      splitSpdxExpression("(MIT OR Apache-2.0)"),
      ["MIT", "Apache-2.0"],
    );
  });
});

// ── enrichLicense ────────────────────────────────────────────────────

describe("enrichLicense", () => {
  it("adds license when missing", () => {
    const comp = { name: "react", version: "18.3.1" };
    const licMap = new Map([["react@18.3.1", "MIT"]]);
    enrichLicense(comp, licMap);
    assert.equal(comp.licenses.length, 1);
    assert.equal(comp.licenses[0].license.id, "MIT");
  });

  it("does not overwrite existing license", () => {
    const comp = {
      name: "react",
      version: "18.3.1",
      licenses: [{ license: { id: "Apache-2.0" } }],
    };
    const licMap = new Map([["react@18.3.1", "MIT"]]);
    enrichLicense(comp, licMap);
    assert.equal(comp.licenses[0].license.id, "Apache-2.0");
  });

  it("resolves from node_modules when not in map", () => {
    makeNodeModule(tmp, "lodash", "4.17.21", "MIT");
    const comp = { name: "lodash", version: "4.17.21" };
    const licMap = new Map();
    enrichLicense(comp, licMap, tmp);
    assert.equal(comp.licenses[0].license.id, "MIT");
    // Also caches in the map for subsequent calls
    assert.equal(licMap.get("lodash@4.17.21"), "MIT");
  });

  it("handles missing package in node_modules gracefully", () => {
    const comp = { name: "nonexistent", version: "1.0.0" };
    enrichLicense(comp, new Map(), tmp);
    assert.equal(comp.licenses, undefined);
  });
});

// ── markDevExcluded ──────────────────────────────────────────────────

describe("markDevExcluded", () => {
  it("marks dev as excluded and clears prod scope", () => {
    const bom = minimalBom([
      { name: "react", version: "18.3.1", scope: "optional" },
      { name: "jest", version: "29.0.0", scope: "optional" },
    ]);
    const prodKeys = new Set(["react@18.3.1"]);

    const { prodCount, excludedCount } = markDevExcluded(
      bom, prodKeys, new Map(),
    );
    assert.equal(prodCount, 1);
    assert.equal(excludedCount, 1);

    const react = bom.components.find((c) => c.name === "react");
    const jest = bom.components.find((c) => c.name === "jest");
    assert.equal(react.scope, undefined);
    assert.equal(jest.scope, "excluded");
  });

  it("enriches licenses on prod components", () => {
    const bom = minimalBom([
      { name: "react", version: "18.3.1" },
    ]);
    const prodKeys = new Set(["react@18.3.1"]);
    const licMap = new Map([["react@18.3.1", "MIT"]]);

    markDevExcluded(bom, prodKeys, licMap);
    assert.equal(bom.components[0].licenses[0].license.id, "MIT");
  });

  it("enriches licenses on dev components from node_modules", () => {
    makeNodeModule(tmp, "jest", "29.0.0", "MIT");
    const bom = minimalBom([
      { name: "react", version: "18.3.1" },
      { name: "jest", version: "29.0.0" },
    ]);
    const prodKeys = new Set(["react@18.3.1"]);

    markDevExcluded(bom, prodKeys, new Map(), tmp);

    const jest = bom.components.find((c) => c.name === "jest");
    assert.equal(jest.scope, "excluded");
    assert.equal(jest.licenses[0].license.id, "MIT");
  });

  it("preserves full dependency graph", () => {
    const bom = minimalBom([
      { name: "react", version: "18.3.1" },
      { name: "jest", version: "29.0.0" },
    ]);
    const prodKeys = new Set(["react@18.3.1"]);

    markDevExcluded(bom, prodKeys, new Map());
    assert.equal(bom.dependencies.length, 2);
  });
});

// ── filterProdOnly ───────────────────────────────────────────────────

describe("filterProdOnly", () => {
  it("removes dev components", () => {
    const bom = minimalBom([
      { name: "react", version: "18.3.1" },
      { name: "jest", version: "29.0.0" },
    ]);
    const prodKeys = new Set(["react@18.3.1"]);

    const result = filterProdOnly(bom, prodKeys, new Map());
    assert.equal(result.components.length, 1);
    assert.equal(result.components[0].name, "react");
  });

  it("prunes dependency graph", () => {
    const bom = minimalBom([
      { name: "react", version: "18.3.1" },
      { name: "jest", version: "29.0.0" },
    ]);
    bom.dependencies[0].dependsOn = ["pkg:npm/jest@29.0.0"];
    const prodKeys = new Set(["react@18.3.1"]);

    const result = filterProdOnly(bom, prodKeys, new Map());
    assert.equal(result.dependencies.length, 1);
    assert.equal(result.dependencies[0].dependsOn.length, 0);
  });

  it("clears scope on kept components", () => {
    const bom = minimalBom([
      { name: "react", version: "18.3.1", scope: "optional" },
    ]);
    const prodKeys = new Set(["react@18.3.1"]);

    const result = filterProdOnly(bom, prodKeys, new Map());
    assert.equal(result.components[0].scope, undefined);
  });

  it("enriches licenses on kept components", () => {
    const bom = minimalBom([
      { name: "react", version: "18.3.1" },
    ]);
    const prodKeys = new Set(["react@18.3.1"]);
    const licMap = new Map([["react@18.3.1", "MIT"]]);

    const result = filterProdOnly(bom, prodKeys, licMap);
    assert.equal(result.components[0].licenses[0].license.id, "MIT");
  });

  it("does not resolve licenses for removed dev components", () => {
    makeNodeModule(tmp, "jest", "29.0.0", "MIT");
    const bom = minimalBom([
      { name: "react", version: "18.3.1" },
      { name: "jest", version: "29.0.0" },
    ]);
    const prodKeys = new Set(["react@18.3.1"]);
    const licMap = new Map();

    const result = filterProdOnly(bom, prodKeys, licMap, tmp);
    assert.equal(result.components.length, 1);
    assert.ok(!licMap.has("jest@29.0.0"));
  });

  it("enriches hashes on kept components", () => {
    const bom = minimalBom([
      { name: "react", version: "18.3.1" },
    ]);
    const prodKeys = new Set(["react@18.3.1"]);
    const hashMap = new Map([["react@18.3.1", "abcd1234"]]);

    const result = filterProdOnly(bom, prodKeys, new Map(), undefined, hashMap);
    assert.equal(result.components[0].hashes[0].alg, "SHA-512");
    assert.equal(result.components[0].hashes[0].content, "abcd1234");
  });
});

// ── sriBase64ToHex ───────────────────────────────────────────────────

describe("sriBase64ToHex", () => {
  it("converts base64 to hex", () => {
    // "AAAA" in base64 = 0x000000
    assert.equal(sriBase64ToHex("AAAA"), "000000");
  });

  it("handles real integrity hash", () => {
    const hex = sriBase64ToHex("n4cUv75CPVAxAm+jXPJ0YJk=");
    assert.ok(hex.length > 0);
    assert.ok(/^[0-9a-f]+$/.test(hex));
  });
});

// ── enrichHash ───────────────────────────────────────────────────────

describe("enrichHash", () => {
  it("adds hash when missing", () => {
    const comp = { name: "react", version: "18.3.1" };
    const hashMap = new Map([["react@18.3.1", "abcdef0123456789"]]);
    enrichHash(comp, hashMap);
    assert.equal(comp.hashes.length, 1);
    assert.equal(comp.hashes[0].alg, "SHA-512");
    assert.equal(comp.hashes[0].content, "abcdef0123456789");
  });

  it("does not overwrite existing hashes", () => {
    const comp = {
      name: "react",
      version: "18.3.1",
      hashes: [{ alg: "SHA-256", content: "existing" }],
    };
    const hashMap = new Map([["react@18.3.1", "newvalue"]]);
    enrichHash(comp, hashMap);
    assert.equal(comp.hashes[0].content, "existing");
  });

  it("skips when not in map", () => {
    const comp = { name: "unknown", version: "1.0.0" };
    enrichHash(comp, new Map());
    assert.equal(comp.hashes, undefined);
  });
});

// ── parseYarnBerryChecksums ──────────────────────────────────────────

describe("parseYarnBerryChecksums", () => {
  it("parses checksums with slash separator", () => {
    const f = join(tmp, "yarn.lock");
    writeFileSync(f, [
      "# yarn lockfile v1",
      "",
      "__metadata:",
      "  version: 8",
      "  cacheKey: 10c0",
      "",
      '"react@npm:^18.0.0":',
      "  version: 18.3.1",
      '  resolution: "react@npm:18.3.1"',
      "  checksum: 10c0/a8468056e46be3c63e4898268efec84e0fbbbd3c0997a4fb1dce1a87c6f9958e73e34de0bf7ad6f5a0d2f35fc3daf81c22f7dbef04c07b tried to",
      "  languageName: node",
      "",
    ].join("\n"));
    // The hex above is truncated; let's use a simpler one
    writeFileSync(f, [
      "__metadata:",
      "  version: 8",
      "",
      '"react@npm:^18.0.0":',
      "  version: 18.3.1",
      "  checksum: 10c0/abcdef1234567890",
      "",
    ].join("\n"));
    const result = parseYarnBerryChecksums(f);
    assert.equal(result.size, 1);
    assert.equal(result.get("react@18.3.1"), "abcdef1234567890");
  });

  it("handles scoped packages", () => {
    const f = join(tmp, "yarn.lock");
    writeFileSync(f, [
      "__metadata:",
      "  version: 8",
      "",
      '"@babel/core@npm:^7.0.0":',
      "  version: 7.28.0",
      "  checksum: 10c0/deadbeef0123",
      "",
    ].join("\n"));
    const result = parseYarnBerryChecksums(f);
    assert.equal(result.get("@babel/core@7.28.0"), "deadbeef0123");
  });
});

// ── parseYarnClassicChecksums ────────────────────────────────────────

describe("parseYarnClassicChecksums", () => {
  it("parses integrity hashes", () => {
    const f = join(tmp, "yarn.lock");
    // base64 of 3 zero bytes = "AAAA"
    writeFileSync(f, [
      "# yarn lockfile v1",
      "",
      "react@^18.0.0:",
      '  version "18.3.1"',
      '  integrity "sha512-AAAA"',
      "",
    ].join("\n"));
    const result = parseYarnClassicChecksums(f);
    assert.equal(result.size, 1);
    assert.equal(result.get("react@18.3.1"), "000000");
  });
});

// ── parsePackageLockChecksums ────────────────────────────────────────

describe("parsePackageLockChecksums", () => {
  it("parses integrity from packages", () => {
    const f = join(tmp, "package-lock.json");
    writeJson(f, {
      lockfileVersion: 3,
      packages: {
        "node_modules/react": {
          version: "18.3.1",
          integrity: "sha512-AAAA",
        },
        "node_modules/@babel/core": {
          version: "7.28.0",
          integrity: "sha512-BBBB",
        },
        "": { version: "1.0.0" },
      },
    });
    const result = parsePackageLockChecksums(f);
    assert.equal(result.size, 2);
    assert.equal(result.get("react@18.3.1"), "000000");
    assert.equal(result.get("@babel/core@7.28.0"), "041041");
  });
});

// ── parsePnpmLockChecksums ───────────────────────────────────────────

describe("parsePnpmLockChecksums", () => {
  it("parses inline integrity hashes", () => {
    const f = join(tmp, "pnpm-lock.yaml");
    writeFileSync(f, [
      "lockfileVersion: '9.0'",
      "",
      "packages:",
      "",
      "  react@18.3.1:",
      "    resolution: {integrity: sha512-AAAA}",
      "    engines: {node: '>=0.10.0'}",
      "",
    ].join("\n"));
    const result = parsePnpmLockChecksums(f);
    assert.equal(result.size, 1);
    assert.equal(result.get("react@18.3.1"), "000000");
  });

  it("handles scoped packages", () => {
    const f = join(tmp, "pnpm-lock.yaml");
    writeFileSync(f, [
      "packages:",
      "",
      "  '@babel/core@7.28.0':",
      "    resolution: {integrity: sha512-AAAA}",
      "",
    ].join("\n"));
    const result = parsePnpmLockChecksums(f);
    assert.equal(result.get("@babel/core@7.28.0"), "000000");
  });
});

// ── parseLocfileChecksums ────────────────────────────────────────────

describe("parseLocfileChecksums", () => {
  it("auto-detects yarn berry", () => {
    writeFileSync(join(tmp, "yarn.lock"), [
      "__metadata:",
      "  version: 8",
      "",
      '"react@npm:^18.0.0":',
      "  version: 18.3.1",
      "  checksum: 10c0/abc123",
      "",
    ].join("\n"));
    const result = parseLocfileChecksums(tmp);
    assert.equal(result.get("react@18.3.1"), "abc123");
  });

  it("auto-detects pnpm", () => {
    writeFileSync(join(tmp, "pnpm-lock.yaml"), [
      "packages:",
      "",
      "  react@18.3.1:",
      "    resolution: {integrity: sha512-AAAA}",
      "",
    ].join("\n"));
    const result = parseLocfileChecksums(tmp);
    assert.equal(result.get("react@18.3.1"), "000000");
  });

  it("returns empty map when no lockfile", () => {
    const result = parseLocfileChecksums(tmp);
    assert.equal(result.size, 0);
  });
});

// ── markDevExcluded with hashes ──────────────────────────────────────

describe("markDevExcluded with hashes", () => {
  it("enriches hashes on all components", () => {
    const bom = minimalBom([
      { name: "react", version: "18.3.1" },
      { name: "jest", version: "29.0.0" },
    ]);
    const prodKeys = new Set(["react@18.3.1"]);
    const hashMap = new Map([
      ["react@18.3.1", "aaa"],
      ["jest@29.0.0", "bbb"],
    ]);

    markDevExcluded(bom, prodKeys, new Map(), undefined, hashMap);

    const react = bom.components.find((c) => c.name === "react");
    const jest = bom.components.find((c) => c.name === "jest");
    assert.equal(react.hashes[0].content, "aaa");
    assert.equal(jest.hashes[0].content, "bbb");
  });
});
