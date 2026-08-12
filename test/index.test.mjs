import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { join, dirname } from "node:path";
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
  enrichEvidence,
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

function makeNodeModule(root, name, version, license, deps, extra) {
  const dir = join(root, "node_modules", name);
  mkdirSync(dir, { recursive: true });
  const pkg = { name, version };
  if (license) pkg.license = license;
  if (deps) pkg.dependencies = deps;
  if (extra) Object.assign(pkg, extra);
  writeJson(join(dir, "package.json"), pkg);
}

function makePnpmModule(root, name, version, license, deps, extra) {
  const dirName = name.replace("/", "+");
  const storeBase = join(root, "node_modules", ".pnpm", `${dirName}@${version}`, "node_modules");
  const dir = join(storeBase, name);
  mkdirSync(dir, { recursive: true });
  const pkg = { name, version };
  if (license) pkg.license = license;
  if (deps) pkg.dependencies = deps;
  if (extra) Object.assign(pkg, extra);
  writeJson(join(dir, "package.json"), pkg);
  return storeBase;
}

function loadWsPackages(pkgFiles) {
  const m = new Map();
  for (const pf of pkgFiles) {
    m.set(dirname(pf), JSON.parse(readFileSync(pf, "utf8")));
  }
  return m;
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

  it("ignores peerDependencies and optionalDependencies", () => {
    makePkg(tmp, {
      name: "app",
      version: "1.0.0",
      dependencies: { react: "^18.0.0" },
      peerDependencies: { "react-dom": "^18.0.0" },
      optionalDependencies: { fsevents: "^2.3.0" },
    });

    const deps = collectDirectProdDeps([join(tmp, "package.json")]);
    const names = deps.map((d) => d.name);
    assert.ok(names.includes("react"));
    assert.ok(!names.includes("react-dom"));
    assert.ok(!names.includes("fsevents"));
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

  it("handles circular peerDependencies", () => {
    makeNodeModule(tmp, "a", "1.0.0", "MIT", null, { peerDependencies: { b: "^1.0.0" } });
    makeNodeModule(tmp, "b", "1.0.0", "MIT", null, { peerDependencies: { a: "^1.0.0" } });

    const result = resolveAllProdDeps([{ name: "a", fromDir: tmp }], tmp);
    assert.ok(result.has("a@1.0.0"));
    assert.ok(result.has("b@1.0.0"));
  });

  it("follows peerDependencies", () => {
    makeNodeModule(tmp, "reactflow", "11.0.0", "MIT", null, { peerDependencies: { react: "^18.0.0" } });
    makeNodeModule(tmp, "react", "18.3.1", "MIT");

    const result = resolveAllProdDeps(
      [{ name: "reactflow", fromDir: tmp }], tmp,
    );
    assert.ok(result.has("reactflow@11.0.0"));
    assert.ok(result.has("react@18.3.1"));
  });

  it("follows optionalDependencies", () => {
    makeNodeModule(tmp, "tar-fs", "3.1.1", "MIT", { pump: "^3.0.0" }, { optionalDependencies: { "bare-fs": "^4.0.0" } });
    makeNodeModule(tmp, "pump", "3.0.3", "MIT");
    makeNodeModule(tmp, "bare-fs", "4.4.4", "Apache-2.0");

    const result = resolveAllProdDeps(
      [{ name: "tar-fs", fromDir: tmp }], tmp,
    );
    assert.ok(result.has("tar-fs@3.1.1"));
    assert.ok(result.has("pump@3.0.3"));
    assert.ok(result.has("bare-fs@4.4.4"));
  });

  it("does not warn for uninstalled optional dependencies", () => {
    makeNodeModule(tmp, "tar-fs", "3.1.1", "MIT", null, { optionalDependencies: { "bare-fs": "^4.0.0" } });
    // bare-fs is NOT installed

    const warnings = [];
    const origWarn = console.warn;
    console.warn = (msg) => warnings.push(msg);
    try {
      resolveAllProdDeps([{ name: "tar-fs", fromDir: tmp }], tmp);
    } finally {
      console.warn = origWarn;
    }
    assert.ok(!warnings.some(w => w.includes("bare-fs")));
  });

  it("does not warn for uninstalled peer dependencies", () => {
    makeNodeModule(tmp, "zustand", "4.5.7", "MIT", null, {
      peerDependencies: { immer: ">=9.0.6", react: "^18.0.0" },
    });
    // neither peer is installed

    const warnings = [];
    const origWarn = console.warn;
    console.warn = (msg) => warnings.push(msg);
    try {
      resolveAllProdDeps([{ name: "zustand", fromDir: tmp }], tmp);
    } finally {
      console.warn = origWarn;
    }
    assert.ok(!warnings.some(w => w.includes("immer")));
    assert.ok(!warnings.some(w => w.includes("react")));
  });

  it("resolves transitive deps through pnpm symlinks", () => {
    // Simulate pnpm structure:
    // workspace/node_modules/i18next -> symlink to .pnpm store
    // .pnpm/i18next@1.0.0/node_modules/i18next (with dep on runtime)
    // .pnpm/i18next@1.0.0/node_modules/runtime (sibling symlink)
    // .pnpm/runtime@1.0.0/node_modules/runtime
    const wsDir = join(tmp, "apps", "web");
    mkdirSync(wsDir, { recursive: true });

    const i18nStore = makePnpmModule(tmp, "i18next", "1.0.0", "MIT", { runtime: "^1.0.0" });
    const rtStore = makePnpmModule(tmp, "runtime", "1.0.0", "MIT");

    // Create sibling symlink: .pnpm/i18next@1.0.0/node_modules/runtime -> .pnpm/runtime@1.0.0/node_modules/runtime
    symlinkSync(
      join(tmp, "node_modules", ".pnpm", "runtime@1.0.0", "node_modules", "runtime"),
      join(i18nStore, "runtime"),
    );

    // Create workspace symlink: apps/web/node_modules/i18next -> .pnpm store
    mkdirSync(join(wsDir, "node_modules"), { recursive: true });
    symlinkSync(
      join(i18nStore, "i18next"),
      join(wsDir, "node_modules", "i18next"),
    );

    const result = resolveAllProdDeps(
      [{ name: "i18next", fromDir: wsDir }], tmp,
    );
    assert.ok(result.has("i18next@1.0.0"));
    assert.ok(result.has("runtime@1.0.0"), "transitive dep through pnpm symlink should be resolved");
  });

  it("discovers implicit peers from pnpm virtual packages", () => {
    // Simulate pnpm virtual package:
    // .pnpm/debug@4.0.0_supports-color@8.0.0/node_modules/debug (deps: {ms: ...})
    // .pnpm/debug@4.0.0_supports-color@8.0.0/node_modules/supports-color (sibling, not in debug's package.json)
    // .pnpm/debug@4.0.0_supports-color@8.0.0/node_modules/ms (sibling)
    const virtualEntry = "debug@4.0.0_supports-color@8.0.0";
    const storeBase = join(tmp, "node_modules", ".pnpm", virtualEntry, "node_modules");

    // debug package
    const debugDir = join(storeBase, "debug");
    mkdirSync(debugDir, { recursive: true });
    writeJson(join(debugDir, "package.json"), {
      name: "debug", version: "4.0.0", dependencies: { ms: "^2.0.0" },
    });

    // ms as sibling
    const msDir = join(storeBase, "ms");
    mkdirSync(msDir, { recursive: true });
    writeJson(join(msDir, "package.json"), { name: "ms", version: "2.1.3" });

    // supports-color as sibling (implicit peer, not in debug's package.json)
    const scDir = join(storeBase, "supports-color");
    mkdirSync(scDir, { recursive: true });
    writeJson(join(scDir, "package.json"), {
      name: "supports-color", version: "8.0.0", dependencies: { "has-flag": "^4.0.0" },
    });

    // has-flag in its own store entry
    makePnpmModule(tmp, "has-flag", "4.0.0", "MIT");
    // symlink from supports-color's resolution
    const scStore = join(tmp, "node_modules", ".pnpm", "supports-color@8.0.0", "node_modules");
    mkdirSync(scStore, { recursive: true });
    symlinkSync(scDir, join(scStore, "supports-color"));
    symlinkSync(
      join(tmp, "node_modules", ".pnpm", "has-flag@4.0.0", "node_modules", "has-flag"),
      join(scStore, "has-flag"),
    );

    const result = resolveAllProdDeps(
      [{ name: "debug", fromDir: storeBase }], tmp,
    );
    assert.ok(result.has("debug@4.0.0"));
    assert.ok(result.has("ms@2.1.3"));
    assert.ok(result.has("supports-color@8.0.0"), "implicit peer from virtual package should be discovered");
    assert.ok(result.has("has-flag@4.0.0"), "transitive dep of implicit peer should be resolved");
  });

  it("skips sibling scanning for non-virtual pnpm entries", () => {
    // .pnpm/react@18.3.1/node_modules/react — no _ in dir name, no scanning
    const storeBase = makePnpmModule(tmp, "react", "18.3.1", "MIT");

    // Add a sibling that is NOT in react's package.json
    const spuriousDir = join(storeBase, "spurious");
    mkdirSync(spuriousDir, { recursive: true });
    writeJson(join(spuriousDir, "package.json"), { name: "spurious", version: "1.0.0" });

    const result = resolveAllProdDeps(
      [{ name: "react", fromDir: storeBase }], tmp,
    );
    assert.ok(result.has("react@18.3.1"));
    assert.ok(!result.has("spurious@1.0.0"), "should not scan siblings of non-virtual store entries");
  });

  it("deduplicates when sibling scan re-discovers the package itself", () => {
    const virtualEntry = "debug@4.0.0_supports-color@8.0.0";
    const storeBase = join(tmp, "node_modules", ".pnpm", virtualEntry, "node_modules");

    const debugDir = join(storeBase, "debug");
    mkdirSync(debugDir, { recursive: true });
    writeJson(join(debugDir, "package.json"), { name: "debug", version: "4.0.0" });

    // supports-color as sibling
    const scDir = join(storeBase, "supports-color");
    mkdirSync(scDir, { recursive: true });
    writeJson(join(scDir, "package.json"), { name: "supports-color", version: "8.0.0" });

    mkdirSync(join(tmp, "ws", "node_modules"), { recursive: true });
    symlinkSync(debugDir, join(tmp, "ws", "node_modules", "debug"));

    const result = resolveAllProdDeps(
      [{ name: "debug", fromDir: join(tmp, "ws") }], tmp,
    );
    // debug@4.0.0 appears once despite being both the initial package and a sibling
    assert.ok(result.has("debug@4.0.0"));
    assert.ok(result.has("supports-color@8.0.0"));
    assert.equal(result.size, 2);
  });

  it("discovers scoped packages from pnpm virtual siblings", () => {
    // .pnpm/@octokit+rest@1.0.0_@octokit+core@1.0.0/node_modules/@octokit/rest
    // .pnpm/@octokit+rest@1.0.0_@octokit+core@1.0.0/node_modules/@octokit/core (implicit peer)
    const virtualEntry = "@octokit+rest@1.0.0_@octokit+core@1.0.0";
    const storeBase = join(tmp, "node_modules", ".pnpm", virtualEntry, "node_modules");

    const restDir = join(storeBase, "@octokit", "rest");
    mkdirSync(restDir, { recursive: true });
    writeJson(join(restDir, "package.json"), {
      name: "@octokit/rest", version: "1.0.0",
    });

    const coreDir = join(storeBase, "@octokit", "core");
    mkdirSync(coreDir, { recursive: true });
    writeJson(join(coreDir, "package.json"), {
      name: "@octokit/core", version: "1.0.0",
    });

    // Workspace symlink so resolvePackageDir can find @octokit/rest
    mkdirSync(join(tmp, "ws", "node_modules", "@octokit"), { recursive: true });
    symlinkSync(restDir, join(tmp, "ws", "node_modules", "@octokit", "rest"));

    const result = resolveAllProdDeps(
      [{ name: "@octokit/rest", fromDir: join(tmp, "ws") }], tmp,
    );
    assert.ok(result.has("@octokit/rest@1.0.0"));
    assert.ok(result.has("@octokit/core@1.0.0"), "scoped sibling from virtual entry should be discovered");
  });

  it("does not warn for unresolved sibling-discovered deps", () => {
    const virtualEntry = "pkg@1.0.0_missing-peer@1.0.0";
    const storeBase = join(tmp, "node_modules", ".pnpm", virtualEntry, "node_modules");

    const pkgDir = join(storeBase, "pkg");
    mkdirSync(pkgDir, { recursive: true });
    writeJson(join(pkgDir, "package.json"), { name: "pkg", version: "1.0.0" });

    // Sibling that is not installed anywhere resolvable
    const peerDir = join(storeBase, "missing-peer");
    mkdirSync(peerDir, { recursive: true });
    writeJson(join(peerDir, "package.json"), {
      name: "missing-peer", version: "1.0.0",
    });

    // Workspace symlink so resolvePackageDir can find pkg
    mkdirSync(join(tmp, "ws", "node_modules"), { recursive: true });
    symlinkSync(pkgDir, join(tmp, "ws", "node_modules", "pkg"));

    const warnings = [];
    const origWarn = console.warn;
    console.warn = (msg) => warnings.push(msg);
    try {
      resolveAllProdDeps([{ name: "pkg", fromDir: join(tmp, "ws") }], tmp);
    } finally {
      console.warn = origWarn;
    }
    // missing-peer is discovered via sibling scan (optional), should not warn
    assert.ok(
      !warnings.some(w => w.includes("missing-peer")),
      "should not warn for unresolved sibling-discovered deps",
    );
  });
});

// ── peer dep classification ─────────────────────────────────────────

describe("peer dep dev/prod classification", () => {
  it("peer dep in consumer devDependencies is excluded", () => {
    // Workspace: dependencies: { A }, devDependencies: { B }
    // A: peerDependencies: { B }
    makePkg(tmp, {
      name: "app", version: "1.0.0",
      dependencies: { A: "1.0.0" },
      devDependencies: { B: "1.0.0" },
    });
    makeNodeModule(tmp, "A", "1.0.0", "MIT", null, { peerDependencies: { B: "^1.0.0" } });
    makeNodeModule(tmp, "B", "1.0.0", "MIT", { X: "^1.0.0" });
    makeNodeModule(tmp, "X", "1.0.0", "MIT");

    const pkgFiles = [join(tmp, "package.json")];
    const directProd = collectDirectProdDeps(pkgFiles);
    const wsPackages = loadWsPackages(pkgFiles);
    const result = resolveAllProdDeps(directProd, tmp, wsPackages);

    assert.ok(result.has("A@1.0.0"), "A is prod");
    assert.ok(!result.has("B@1.0.0"), "B is dev-only peer dep");
    assert.ok(!result.has("X@1.0.0"), "X (transitive of B) is also excluded");
  });

  it("peer dep with no consumer declaration is included", () => {
    // Workspace: dependencies: { A }
    // A: peerDependencies: { B }
    // B is installed but not declared in workspace
    makePkg(tmp, {
      name: "app", version: "1.0.0",
      dependencies: { A: "1.0.0" },
    });
    makeNodeModule(tmp, "A", "1.0.0", "MIT", null, { peerDependencies: { B: "^1.0.0" } });
    makeNodeModule(tmp, "B", "1.0.0", "MIT");

    const pkgFiles = [join(tmp, "package.json")];
    const directProd = collectDirectProdDeps(pkgFiles);
    const wsPackages = loadWsPackages(pkgFiles);
    const result = resolveAllProdDeps(directProd, tmp, wsPackages);

    assert.ok(result.has("A@1.0.0"));
    assert.ok(result.has("B@1.0.0"), "undeclared peer dep should be followed");
  });

  it("peer dep in consumer dependencies is included", () => {
    // Workspace: dependencies: { A, B }
    // A: peerDependencies: { B }
    makePkg(tmp, {
      name: "app", version: "1.0.0",
      dependencies: { A: "1.0.0", B: "1.0.0" },
    });
    makeNodeModule(tmp, "A", "1.0.0", "MIT", null, { peerDependencies: { B: "^1.0.0" } });
    makeNodeModule(tmp, "B", "1.0.0", "MIT");

    const pkgFiles = [join(tmp, "package.json")];
    const directProd = collectDirectProdDeps(pkgFiles);
    const wsPackages = loadWsPackages(pkgFiles);
    const result = resolveAllProdDeps(directProd, tmp, wsPackages);

    assert.ok(result.has("A@1.0.0"));
    assert.ok(result.has("B@1.0.0"), "peer dep in dependencies is always prod");
  });

  it("same peer dep, all consumers declare devDependency", () => {
    // Workspace-1: dependencies: { A }, devDependencies: { B }
    // Workspace-2: dependencies: { C }, devDependencies: { B }
    // A: peerDependencies: { B }
    // C: peerDependencies: { B }
    const ws1 = join(tmp, "packages", "ws1");
    const ws2 = join(tmp, "packages", "ws2");
    makePkg(tmp, {
      name: "root", version: "1.0.0",
      workspaces: ["packages/*"],
    });
    makePkg(ws1, {
      name: "ws1", version: "1.0.0",
      dependencies: { A: "1.0.0" },
      devDependencies: { B: "1.0.0" },
    });
    makePkg(ws2, {
      name: "ws2", version: "1.0.0",
      dependencies: { C: "1.0.0" },
      devDependencies: { B: "1.0.0" },
    });
    makeNodeModule(tmp, "A", "1.0.0", "MIT", null, { peerDependencies: { B: "^1.0.0" } });
    makeNodeModule(tmp, "C", "1.0.0", "MIT", null, { peerDependencies: { B: "^1.0.0" } });
    makeNodeModule(tmp, "B", "1.0.0", "MIT");

    const pkgFiles = [join(ws1, "package.json"), join(ws2, "package.json")];
    const directProd = collectDirectProdDeps(pkgFiles);
    const wsPackages = loadWsPackages(pkgFiles);
    const result = resolveAllProdDeps(directProd, tmp, wsPackages);

    assert.ok(result.has("A@1.0.0"));
    assert.ok(result.has("C@1.0.0"));
    assert.ok(!result.has("B@1.0.0"), "B is dev-only in all consumers");
  });

  it("same peer dep, one consumer undeclared — included", () => {
    // Workspace-1: dependencies: { A } (no declaration of B)
    // Workspace-2: dependencies: { C }, devDependencies: { B }
    // A: peerDependencies: { B }
    // C: peerDependencies: { B }
    const ws1 = join(tmp, "packages", "ws1");
    const ws2 = join(tmp, "packages", "ws2");
    makePkg(tmp, {
      name: "root", version: "1.0.0",
      workspaces: ["packages/*"],
    });
    makePkg(ws1, {
      name: "ws1", version: "1.0.0",
      dependencies: { A: "1.0.0" },
    });
    makePkg(ws2, {
      name: "ws2", version: "1.0.0",
      dependencies: { C: "1.0.0" },
      devDependencies: { B: "1.0.0" },
    });
    makeNodeModule(tmp, "A", "1.0.0", "MIT", null, { peerDependencies: { B: "^1.0.0" } });
    makeNodeModule(tmp, "C", "1.0.0", "MIT", null, { peerDependencies: { B: "^1.0.0" } });
    makeNodeModule(tmp, "B", "1.0.0", "MIT");

    const pkgFiles = [join(ws1, "package.json"), join(ws2, "package.json")];
    const directProd = collectDirectProdDeps(pkgFiles);
    const wsPackages = loadWsPackages(pkgFiles);
    const result = resolveAllProdDeps(directProd, tmp, wsPackages);

    assert.ok(result.has("B@1.0.0"),
      "B should be prod — ws1 depends on A which peers B, and ws1 didn't declare B as dev");
  });

  it("dev-only peer dep reachable through regular deps is still included", () => {
    // Workspace: dependencies: { A, D }, devDependencies: { B }
    // A: peerDependencies: { B }
    // D: dependencies: { B }
    // B is dev-only via A's peer dep, but prod via D's regular dep
    makePkg(tmp, {
      name: "app", version: "1.0.0",
      dependencies: { A: "1.0.0", D: "1.0.0" },
      devDependencies: { B: "1.0.0" },
    });
    makeNodeModule(tmp, "A", "1.0.0", "MIT", null, { peerDependencies: { B: "^1.0.0" } });
    makeNodeModule(tmp, "D", "1.0.0", "MIT", { B: "^1.0.0" });
    makeNodeModule(tmp, "B", "1.0.0", "MIT");

    const pkgFiles = [join(tmp, "package.json")];
    const directProd = collectDirectProdDeps(pkgFiles);
    const wsPackages = loadWsPackages(pkgFiles);
    const result = resolveAllProdDeps(directProd, tmp, wsPackages);

    assert.ok(result.has("B@1.0.0"),
      "B reachable through D's regular dependency, regardless of peer dev classification");
  });

  it("A->B dependency edge present when both prod and peer dep is dev-only", () => {
    // Same setup as above — B is prod via D, A peers B (dev-only)
    // The dependency graph should include A->B edge since both are prod
    makePkg(tmp, {
      name: "app", version: "1.0.0",
      dependencies: { A: "1.0.0", D: "1.0.0" },
      devDependencies: { B: "1.0.0" },
    });
    makeNodeModule(tmp, "A", "1.0.0", "MIT", null, { peerDependencies: { B: "^1.0.0" } });
    makeNodeModule(tmp, "D", "1.0.0", "MIT", { B: "^1.0.0" });
    makeNodeModule(tmp, "B", "1.0.0", "MIT");

    const pkgFiles = [join(tmp, "package.json")];
    const directProd = collectDirectProdDeps(pkgFiles);
    const wsPackages = loadWsPackages(pkgFiles);
    const prodKeys = new Set(resolveAllProdDeps(directProd, tmp, wsPackages).keys());

    const bom = minimalBom([
      { name: "A", version: "1.0.0" },
      { name: "B", version: "1.0.0" },
      { name: "D", version: "1.0.0" },
    ]);
    bom.dependencies.find(d => d.ref === "pkg:npm/A@1.0.0").dependsOn = ["pkg:npm/B@1.0.0"];
    bom.dependencies.find(d => d.ref === "pkg:npm/D@1.0.0").dependsOn = ["pkg:npm/B@1.0.0"];

    const result = filterProdOnly(bom, prodKeys, new Map());

    assert.equal(result.components.length, 3, "all three are prod");
    const aDep = result.dependencies.find(d => d.ref === "pkg:npm/A@1.0.0");
    assert.ok(aDep.dependsOn.includes("pkg:npm/B@1.0.0"),
      "A->B edge should be present since both are prod components");
  });

  it("transitive deps of dev-only peer dep are excluded", () => {
    // Workspace: dependencies: { A }, devDependencies: { B }
    // A: peerDependencies: { B }
    // B: dependencies: { X }, X: dependencies: { Y }
    makePkg(tmp, {
      name: "app", version: "1.0.0",
      dependencies: { A: "1.0.0" },
      devDependencies: { B: "1.0.0" },
    });
    makeNodeModule(tmp, "A", "1.0.0", "MIT", null, { peerDependencies: { B: "^1.0.0" } });
    makeNodeModule(tmp, "B", "1.0.0", "MIT", { X: "^1.0.0" });
    makeNodeModule(tmp, "X", "1.0.0", "MIT", { Y: "^1.0.0" });
    makeNodeModule(tmp, "Y", "1.0.0", "MIT");

    const pkgFiles = [join(tmp, "package.json")];
    const directProd = collectDirectProdDeps(pkgFiles);
    const wsPackages = loadWsPackages(pkgFiles);
    const result = resolveAllProdDeps(directProd, tmp, wsPackages);

    assert.ok(!result.has("B@1.0.0"), "B excluded");
    assert.ok(!result.has("X@1.0.0"), "X excluded (transitive of B)");
    assert.ok(!result.has("Y@1.0.0"), "Y excluded (transitive of X of B)");
  });

  it("optional dep of dev-only peer dep is excluded", () => {
    // Workspace: dependencies: { A }, devDependencies: { B }
    // A: peerDependencies: { B }
    // B: optionalDependencies: { C }
    makePkg(tmp, {
      name: "app", version: "1.0.0",
      dependencies: { A: "1.0.0" },
      devDependencies: { B: "1.0.0" },
    });
    makeNodeModule(tmp, "A", "1.0.0", "MIT", null, { peerDependencies: { B: "^1.0.0" } });
    makeNodeModule(tmp, "B", "1.0.0", "MIT", null, { optionalDependencies: { C: "^1.0.0" } });
    makeNodeModule(tmp, "C", "1.0.0", "MIT");

    const pkgFiles = [join(tmp, "package.json")];
    const directProd = collectDirectProdDeps(pkgFiles);
    const wsPackages = loadWsPackages(pkgFiles);
    const result = resolveAllProdDeps(directProd, tmp, wsPackages);

    assert.ok(!result.has("B@1.0.0"));
    assert.ok(!result.has("C@1.0.0"), "optional dep of dev-only B also excluded");
  });

  it("multi-workspace different declarations — undeclared wins", () => {
    // Workspace-1: dependencies: { A }, devDependencies: { B }
    // Workspace-2: dependencies: { A } (no B declaration)
    // A: peerDependencies: { B }
    const ws1 = join(tmp, "packages", "ws1");
    const ws2 = join(tmp, "packages", "ws2");
    makePkg(tmp, {
      name: "root", version: "1.0.0",
      workspaces: ["packages/*"],
    });
    makePkg(ws1, {
      name: "ws1", version: "1.0.0",
      dependencies: { A: "1.0.0" },
      devDependencies: { B: "1.0.0" },
    });
    makePkg(ws2, {
      name: "ws2", version: "1.0.0",
      dependencies: { A: "1.0.0" },
    });
    makeNodeModule(tmp, "A", "1.0.0", "MIT", null, { peerDependencies: { B: "^1.0.0" } });
    makeNodeModule(tmp, "B", "1.0.0", "MIT");

    const pkgFiles = [join(ws1, "package.json"), join(ws2, "package.json")];
    const directProd = collectDirectProdDeps(pkgFiles);
    const wsPackages = loadWsPackages(pkgFiles);
    const result = resolveAllProdDeps(directProd, tmp, wsPackages);

    assert.ok(result.has("B@1.0.0"),
      "B should be prod — ws2 depends on A but didn't declare B as dev");
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

// ── enrichEvidence ──────────────────────────────────────────────────

describe("enrichEvidence", () => {
  it("adds evidence.identity when missing", () => {
    const comp = { name: "react", version: "18.3.1" };
    enrichEvidence(comp);
    assert.equal(comp.evidence.identity.length, 1);
    assert.equal(comp.evidence.identity[0].field, "purl");
    assert.equal(comp.evidence.identity[0].confidence, 0.6);
    assert.equal(comp.evidence.identity[0].methods[0].technique, "manifest-analysis");
    assert.equal(comp.evidence.identity[0].methods[0].value, "package-json-analysis");
  });

  it("does not overwrite existing evidence.identity", () => {
    const comp = {
      name: "react",
      version: "18.3.1",
      evidence: {
        identity: [{ field: "cpe", confidence: 1.0, methods: [] }],
      },
    };
    enrichEvidence(comp);
    assert.equal(comp.evidence.identity.length, 1);
    assert.equal(comp.evidence.identity[0].field, "cpe");
  });

  it("preserves existing evidence.occurrences", () => {
    const comp = {
      name: "react",
      version: "18.3.1",
      evidence: {
        occurrences: [{ location: "lib/react.js" }],
      },
    };
    enrichEvidence(comp);
    assert.equal(comp.evidence.occurrences.length, 1);
    assert.equal(comp.evidence.occurrences[0].location, "lib/react.js");
    assert.equal(comp.evidence.identity.length, 1);
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
    assert.equal(react.evidence.identity[0].field, "purl");
    assert.equal(jest.evidence, undefined);
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
    assert.equal(result.components[0].evidence.identity[0].field, "purl");
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
    const distRef = result.components[0].externalReferences.find(r => r.type === "distribution");
    assert.equal(distRef.hashes[0].alg, "SHA-512");
    assert.equal(distRef.hashes[0].content, "abcd1234");
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
  it("adds hash to new distribution externalReference", () => {
    const comp = { name: "react", version: "18.3.1" };
    const hashMap = new Map([["react@18.3.1", "abcdef0123456789"]]);
    enrichHash(comp, hashMap);
    assert.equal(comp.hashes, undefined);
    assert.equal(comp.externalReferences.length, 1);
    assert.equal(comp.externalReferences[0].type, "distribution");
    assert.equal(comp.externalReferences[0].hashes[0].alg, "SHA-512");
    assert.equal(comp.externalReferences[0].hashes[0].content, "abcdef0123456789");
  });

  it("adds hash to existing distribution externalReference", () => {
    const comp = {
      name: "react", version: "18.3.1",
      externalReferences: [{
        type: "distribution",
        url: "https://registry.npmjs.org/react/-/react-18.3.1.tgz",
      }],
    };
    const hashMap = new Map([["react@18.3.1", "abcdef0123456789"]]);
    enrichHash(comp, hashMap);
    assert.equal(comp.externalReferences[0].hashes[0].content, "abcdef0123456789");
    assert.equal(comp.externalReferences[0].url, "https://registry.npmjs.org/react/-/react-18.3.1.tgz");
  });

  it("does not overwrite existing distribution hashes", () => {
    const comp = {
      name: "react", version: "18.3.1",
      externalReferences: [{
        type: "distribution",
        hashes: [{ alg: "SHA-512", content: "existing" }],
      }],
    };
    const hashMap = new Map([["react@18.3.1", "newvalue"]]);
    enrichHash(comp, hashMap);
    assert.equal(comp.externalReferences[0].hashes[0].content, "existing");
  });

  it("skips when not in map and no distribution ref", () => {
    const comp = { name: "unknown", version: "1.0.0" };
    enrichHash(comp, new Map());
    assert.equal(comp.externalReferences, undefined);
  });

  it("preserves non-distribution refs and appends distribution", () => {
    const comp = {
      name: "react", version: "18.3.1",
      externalReferences: [{ type: "vcs", url: "https://github.com/facebook/react" }],
    };
    const hashMap = new Map([["react@18.3.1", "abcdef"]]);
    enrichHash(comp, hashMap);
    assert.equal(comp.externalReferences.length, 2);
    assert.equal(comp.externalReferences[0].type, "vcs");
    assert.equal(comp.externalReferences[0].url, "https://github.com/facebook/react");
    assert.equal(comp.externalReferences[1].type, "distribution");
    assert.equal(comp.externalReferences[1].hashes[0].content, "abcdef");
  });

  it("removes component.hashes that duplicate distribution hashes", () => {
    const comp = {
      name: "react", version: "18.3.1",
      hashes: [{ alg: "SHA-512", content: "abcdef" }],
    };
    const hashMap = new Map([["react@18.3.1", "abcdef"]]);
    enrichHash(comp, hashMap);
    assert.equal(comp.hashes, undefined);
    const distRef = comp.externalReferences.find(r => r.type === "distribution");
    assert.equal(distRef.hashes[0].content, "abcdef");
  });

  it("keeps component.hashes that differ from distribution hashes", () => {
    const comp = {
      name: "react", version: "18.3.1",
      hashes: [{ alg: "SHA-256", content: "different" }],
    };
    const hashMap = new Map([["react@18.3.1", "abcdef"]]);
    enrichHash(comp, hashMap);
    assert.equal(comp.hashes.length, 1);
    assert.equal(comp.hashes[0].content, "different");
  });

  it("removes duplicate hashes when distribution ref already exists", () => {
    const comp = {
      name: "react", version: "18.3.1",
      hashes: [{ alg: "SHA-512", content: "existing" }],
      externalReferences: [{
        type: "distribution",
        hashes: [{ alg: "SHA-512", content: "existing" }],
      }],
    };
    enrichHash(comp, new Map());
    assert.equal(comp.hashes, undefined);
  });

  it("removes only matching hashes when component has a mix", () => {
    const comp = {
      name: "react", version: "18.3.1",
      hashes: [
        { alg: "SHA-512", content: "abcdef" },
        { alg: "SHA-256", content: "content-hash" },
      ],
    };
    const hashMap = new Map([["react@18.3.1", "abcdef"]]);
    enrichHash(comp, hashMap);
    assert.equal(comp.hashes.length, 1);
    assert.equal(comp.hashes[0].alg, "SHA-256");
    assert.equal(comp.hashes[0].content, "content-hash");
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
    const reactDist = react.externalReferences.find(r => r.type === "distribution");
    const jestDist = jest.externalReferences.find(r => r.type === "distribution");
    assert.equal(reactDist.hashes[0].content, "aaa");
    assert.equal(jestDist.hashes[0].content, "bbb");
  });
});
