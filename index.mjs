#!/usr/bin/env node

/**
 * Enriches a CycloneDX SBOM for a Node.js project with accurate
 * dependency scope and missing license data.
 *
 * Works with SBOMs from any generator (cdxgen, @cyclonedx/yarn-plugin,
 * npm sbom, pnpm sbom).  The enrichment walks package.json
 * "dependencies" (not "devDependencies") across all workspaces to
 * classify each component as production or dev-only — a more reliable
 * signal than lockfile-based heuristics.
 *
 * By default, keeps all components but marks dev-only ones with
 * CycloneDX scope "excluded" (not reachable at runtime).  Production
 * components have their scope cleared (implied "required" per spec).
 *
 * With --prod-only, strips dev-only components and their dependency
 * entries entirely.
 *
 * Components that lack license metadata are enriched by reading the
 * license field from the resolved package.json in node_modules.
 * Components that lack hashes are enriched from the lockfile
 * (yarn.lock, pnpm-lock.yaml, or package-lock.json).
 *
 * Supports npm/yarn workspaces (package.json "workspaces" field)
 * and pnpm workspaces (pnpm-workspace.yaml).
 *
 * Usage:
 *   cdx-npm-enrich [options] <bom.cdx.json>
 *
 * Options:
 *   --project-dir <dir>      Project root with package.json and node_modules
 *                            (default: current working directory)
 *   -o, --output <file>      Write to file instead of modifying in-place
 *   --prod-only              Strip dev components instead of marking excluded
 */

import { readFileSync, writeFileSync, readdirSync, existsSync, realpathSync } from "fs";
import { join, dirname, resolve } from "path";
import { fileURLToPath } from "url";

// ── Workspace discovery ──────────────────────────────────────────────

/**
 * Expand workspace glob patterns into package.json paths.
 * Handles both simple directory names and trailing-wildcard globs
 * (e.g., "packages/*").
 */
export function expandWorkspacePatterns(rootDir, patterns) {
  const pkgFiles = [];
  for (const ws of patterns) {
    if (ws.includes("*")) {
      const base = ws.replace(/\/?\*+$/, "");
      const dir = join(rootDir, base);
      if (!existsSync(dir)) {
        console.warn(`Warning: workspace directory '${base}' does not exist`);
        continue;
      }
      for (const entry of readdirSync(dir)) {
        const pj = join(dir, entry, "package.json");
        if (existsSync(pj)) pkgFiles.push(pj);
      }
    } else {
      const pj = join(rootDir, ws, "package.json");
      if (existsSync(pj)) pkgFiles.push(pj);
    }
  }
  return pkgFiles;
}

/**
 * Parse pnpm-workspace.yaml to extract the packages list.
 * Uses simple line-by-line parsing — no YAML library needed
 * for this flat structure.
 */
export function parsePnpmWorkspaceYaml(filePath) {
  const lines = readFileSync(filePath, "utf8").split("\n");
  const patterns = [];
  let inPackages = false;
  for (const line of lines) {
    if (/^packages:\s*$/.test(line)) {
      inPackages = true;
      continue;
    }
    if (inPackages && /^\S/.test(line) && line.trim() !== "") {
      break;
    }
    if (inPackages) {
      const match = line.match(/^\s+-\s+['"]?([^'"]+)['"]?\s*$/);
      if (match) patterns.push(match[1]);
    }
  }
  return patterns;
}

/**
 * Collect package.json paths for the root and all workspace packages.
 * Supports npm/yarn (package.json "workspaces") and pnpm
 * (pnpm-workspace.yaml).
 */
export function discoverWorkspacePackages(rootDir) {
  const rootPkgPath = join(rootDir, "package.json");
  if (!existsSync(rootPkgPath)) {
    console.error(`Error: no package.json found in ${rootDir}`);
    process.exit(1);
  }
  const rootPkg = JSON.parse(readFileSync(rootPkgPath, "utf8"));
  const pkgFiles = [rootPkgPath];

  // npm/yarn workspaces (package.json "workspaces" field)
  const wsField = rootPkg.workspaces;
  const wsPatterns = Array.isArray(wsField)
    ? wsField
    : Array.isArray(wsField?.packages)
      ? wsField.packages
      : [];
  if (wsPatterns.length > 0) {
    pkgFiles.push(...expandWorkspacePatterns(rootDir, wsPatterns));
    return pkgFiles;
  }

  // pnpm workspaces (pnpm-workspace.yaml)
  const pnpmWsPath = join(rootDir, "pnpm-workspace.yaml");
  if (existsSync(pnpmWsPath)) {
    const patterns = parsePnpmWorkspaceYaml(pnpmWsPath);
    pkgFiles.push(...expandWorkspacePatterns(rootDir, patterns));
  }

  return pkgFiles;
}

// ── Production dependency collection ─────────────────────────────────

/**
 * Collect direct production dependencies from package.json files,
 * skipping workspace: references (local packages, not npm deps).
 * Returns an array of {name, fromDir} so that resolution starts
 * from the correct workspace directory (important for pnpm which
 * only creates symlinks in per-workspace node_modules).
 */
export function collectDirectProdDeps(pkgFiles) {
  const deps = [];
  const seen = new Set();
  for (const pf of pkgFiles) {
    const pkg = JSON.parse(readFileSync(pf, "utf8"));
    const wsDir = dirname(pf);
    for (const dep of Object.keys(pkg.dependencies || {})) {
      if (!(pkg.dependencies[dep] || "").startsWith("workspace:")) {
        const key = `${dep}@${wsDir}`;
        if (!seen.has(key)) {
          seen.add(key);
          deps.push({ name: dep, fromDir: wsDir });
        }
      }
    }
  }
  return deps;
}

/**
 * Walk up from fromDir checking node_modules at each level.
 * Falls back to the project root node_modules, then to the
 * pnpm content-addressable store (.pnpm directory).
 */
export function resolvePackageDir(name, fromDir, rootDir) {
  // Standard node_modules walk (works for npm, yarn, and pnpm direct deps)
  let dir = fromDir;
  while (dir !== dirname(dir)) {
    const candidate = join(dir, "node_modules", name, "package.json");
    if (existsSync(candidate)) return join(dir, "node_modules", name);
    dir = dirname(dir);
  }
  const fallback = join(rootDir, "node_modules", name);
  if (existsSync(join(fallback, "package.json"))) return fallback;

  // pnpm virtual store: transitive deps live in
  // node_modules/.pnpm/<name>@<version>/node_modules/<name>/
  // Scoped packages use + instead of / in directory names.
  const pnpmStore = join(rootDir, "node_modules", ".pnpm");
  if (existsSync(pnpmStore)) {
    const dirName = name.replace("/", "+");
    try {
      for (const entry of readdirSync(pnpmStore)) {
        if (entry.startsWith(dirName + "@")) {
          const candidate = join(pnpmStore, entry, "node_modules", name);
          if (existsSync(join(candidate, "package.json"))) return candidate;
        }
      }
    } catch { /* ignore read errors */ }
  }
  return null;
}

/**
 * Transitively resolve all production dependencies starting from
 * the direct prod deps.  Returns a Map of "name@version" -> info.
 */
export function resolveAllProdDeps(directProd, rootDir) {
  const allProd = new Map();
  const queue = [...directProd];

  while (queue.length) {
    const { name, fromDir } = queue.pop();
    const pkgDir = resolvePackageDir(name, fromDir, rootDir);
    if (!pkgDir) {
      console.warn(
        `Warning: could not resolve production dependency '${name}'`,
      );
      continue;
    }
    try {
      const pkg = JSON.parse(
        readFileSync(join(pkgDir, "package.json"), "utf8"),
      );
      const ver = pkg.version || "0";
      const key = `${name}@${ver}`;
      if (allProd.has(key)) continue;
      allProd.set(key, { name, version: ver, license: pkg.license });
      for (const dep of Object.keys(pkg.dependencies || {})) {
        queue.push({ name: dep, fromDir: pkgDir });
      }
    } catch (e) {
      console.warn(
        `Warning: could not read package.json for '${name}' in ${pkgDir}: ${e.message}`,
      );
    }
  }
  return allProd;
}

// ── License helpers ──────────────────────────────────────────────────

export function spdxUrl(id) {
  if (!id || /[\s()]/.test(id)) return undefined;
  return `https://spdx.org/licenses/${id}.html`;
}

export function buildLicenseEntry(id, url) {
  const entry = { id };
  const resolved = url || spdxUrl(id);
  if (resolved) entry.url = resolved;
  return { license: entry };
}

export function splitSpdxExpression(expr) {
  return expr
    .replace(/[()]/g, "")
    .split(/\s+(?:OR|AND)\s+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** Build a CycloneDX licenses array from a package.json license field. */
export function buildLicenses(license) {
  if (typeof license === "string") {
    if (/\s(?:OR|AND)\s/.test(license)) {
      return splitSpdxExpression(license).map((id) => buildLicenseEntry(id));
    }
    return [buildLicenseEntry(license)];
  }
  if (Array.isArray(license)) {
    return license.map((l) =>
      typeof l === "string"
        ? buildLicenseEntry(l)
        : buildLicenseEntry(l.type || l.name, l.url),
    );
  }
  if (typeof license === "object" && license !== null) {
    return [buildLicenseEntry(license.type || license.name, license.url)];
  }
  return [];
}

// ── Hash enrichment ──────────────────────────────────────────────────

/**
 * Parse a Yarn Berry (v2+) lockfile and extract checksums.
 * Format: `checksum: 10c0/<sha512hex>` (the prefix before the
 * slash is a yarn internal cache key version).
 * Returns a Map of "name@version" -> sha512 hex string.
 */
export function parseYarnBerryChecksums(filePath) {
  const hashes = new Map();
  const content = readFileSync(filePath, "utf8");
  let currentName = null;
  let currentVersion = null;
  for (const line of content.split("\n")) {
    // Package header: "name@npm:range":
    const headerMatch = line.match(/^"?(@?[^@"]+)@npm:/);
    if (headerMatch) {
      currentName = headerMatch[1];
      currentVersion = null;
      continue;
    }
    if (currentName) {
      const verMatch = line.match(/^\s+version:\s+(.+)$/);
      if (verMatch) {
        currentVersion = verMatch[1].trim();
        continue;
      }
      const csMatch = line.match(/^\s+checksum:\s+(?:\w+[/-])?([0-9a-f]+)$/);
      if (csMatch && currentVersion) {
        hashes.set(`${currentName}@${currentVersion}`, csMatch[1]);
        continue;
      }
      // New top-level entry resets state
      if (/^\S/.test(line) && line.trim() !== "") {
        currentName = null;
        currentVersion = null;
      }
    }
  }
  return hashes;
}

/**
 * Parse a Yarn Classic (v1) lockfile and extract integrity hashes.
 * Format: `integrity "sha512-<base64>"`
 * Returns a Map of "name@version" -> sha512 hex string.
 */
export function parseYarnClassicChecksums(filePath) {
  const hashes = new Map();
  const content = readFileSync(filePath, "utf8");
  let currentName = null;
  let currentVersion = null;
  for (const line of content.split("\n")) {
    // Package header: name@range:
    const headerMatch = line.match(/^"?(@?[^@"]+)@/);
    if (headerMatch && !line.startsWith(" ")) {
      currentName = headerMatch[1];
      currentVersion = null;
      continue;
    }
    if (currentName) {
      const verMatch = line.match(/^\s+version\s+"(.+)"$/);
      if (verMatch) {
        currentVersion = verMatch[1];
        continue;
      }
      const intMatch = line.match(/^\s+integrity\s+"?sha512-([A-Za-z0-9+/=]+)"?$/);
      if (intMatch && currentVersion) {
        hashes.set(`${currentName}@${currentVersion}`, sriBase64ToHex(intMatch[1]));
      }
    }
  }
  return hashes;
}

/**
 * Parse a package-lock.json (npm) and extract integrity hashes.
 * Format: `"integrity": "sha512-<base64>"`
 * Returns a Map of "name@version" -> sha512 hex string.
 */
export function parsePackageLockChecksums(filePath) {
  const hashes = new Map();
  const lockfile = JSON.parse(readFileSync(filePath, "utf8"));
  const packages = lockfile.packages || {};
  for (const [path, info] of Object.entries(packages)) {
    if (!path || !info.version || !info.integrity) continue;
    const match = info.integrity.match(/^sha512-([A-Za-z0-9+/=]+)$/);
    if (!match) continue;
    // path is like "node_modules/react" or "node_modules/@babel/core"
    const name = path.replace(/^.*node_modules\//, "");
    hashes.set(`${name}@${info.version}`, sriBase64ToHex(match[1]));
  }
  return hashes;
}

/**
 * Parse a pnpm-lock.yaml and extract integrity hashes.
 * The integrity appears inline: `resolution: {integrity: sha512-<base64>}`
 * or on its own line: `integrity: sha512-<base64>`
 * Returns a Map of "name@version" -> sha512 hex string.
 */
export function parsePnpmLockChecksums(filePath) {
  const hashes = new Map();
  const content = readFileSync(filePath, "utf8");
  let inPackages = false;
  let currentPkg = null;
  for (const line of content.split("\n")) {
    if (/^packages:/.test(line)) {
      inPackages = true;
      continue;
    }
    if (inPackages && /^\S/.test(line) && line.trim() !== "" && !line.startsWith(" ")) {
      inPackages = false;
      continue;
    }
    if (!inPackages) continue;
    // Package entry: "  name@version:" or "  '@scope/name@version':"
    const pkgMatch = line.match(/^\s{2}'?(@?[^@']+)@([^':]+)'?:/);
    if (pkgMatch) {
      currentPkg = { name: pkgMatch[1], version: pkgMatch[2] };
      continue;
    }
    if (currentPkg) {
      // Integrity can be inline in resolution or on its own line
      const intMatch = line.match(/sha512-([A-Za-z0-9+/=]+)/);
      if (intMatch) {
        hashes.set(
          `${currentPkg.name}@${currentPkg.version}`,
          sriBase64ToHex(intMatch[1]),
        );
      }
    }
  }
  return hashes;
}

/** Convert a base64-encoded SRI hash to a hex string. */
export function sriBase64ToHex(b64) {
  return Buffer.from(b64, "base64").toString("hex");
}

/**
 * Detect the lockfile format and parse checksums.
 * Returns a Map of "name@version" -> sha512 hex string.
 */
export function parseLocfileChecksums(rootDir) {
  // Yarn Berry (v2+): has "checksum:" lines and "__metadata:" header
  const yarnLock = join(rootDir, "yarn.lock");
  if (existsSync(yarnLock)) {
    const head = readFileSync(yarnLock, "utf8").slice(0, 500);
    if (head.includes("__metadata:")) {
      return parseYarnBerryChecksums(yarnLock);
    }
    return parseYarnClassicChecksums(yarnLock);
  }
  // pnpm
  const pnpmLock = join(rootDir, "pnpm-lock.yaml");
  if (existsSync(pnpmLock)) {
    return parsePnpmLockChecksums(pnpmLock);
  }
  // npm
  const pkgLock = join(rootDir, "package-lock.json");
  if (existsSync(pkgLock)) {
    return parsePackageLockChecksums(pkgLock);
  }
  return new Map();
}

/** Add a SHA-512 hash to a component if it doesn't already have one. */
export function enrichHash(component, hashMap) {
  if (component.hashes && component.hashes.length > 0) return;
  const hex = hashMap.get(componentKey(component));
  if (hex) {
    component.hashes = [{ alg: "SHA-512", content: hex }];
  }
}

/** Add evidence.identity to a component confirming its PURL via manifest analysis. */
export function enrichEvidence(component) {
  const evidence = component.evidence || (component.evidence = {});
  if (evidence.identity && evidence.identity.length > 0) return;
  evidence.identity = [{
    field: "purl",
    confidence: 0.6,
    methods: [{
      technique: "manifest-analysis",
      value: "package-json-analysis",
    }],
  }];
}

// ── SBOM processing ──────────────────────────────────────────────────

/** Build a component key from its group, name, and version. */
export function componentKey(c) {
  const fullName = c.group ? `${c.group}/${c.name}` : c.name;
  return `${fullName}@${c.version}`;
}

/** Enrich a component's license if missing, using the pre-built map
 *  or resolving from node_modules on demand. */
export function enrichLicense(component, licensesByKey, rootDir) {
  if (component.licenses && component.licenses.length > 0) return;
  const key = componentKey(component);
  let license = licensesByKey.get(key);
  if (!license && rootDir) {
    const name = component.group
      ? `${component.group}/${component.name}`
      : component.name;
    const pkgDir = resolvePackageDir(name, rootDir, rootDir);
    if (pkgDir) {
      try {
        const pkg = JSON.parse(
          readFileSync(join(pkgDir, "package.json"), "utf8"),
        );
        license = pkg.license;
        if (license) licensesByKey.set(key, license);
      } catch { /* ignore */ }
    }
  }
  if (license) {
    component.licenses = buildLicenses(license);
  }
}

/**
 * Mark dev-only components with scope "excluded" and enrich licenses.
 * Keeps all components and the full dependency graph.
 * Returns the modified bom.
 */
export function markDevExcluded(bom, prodKeys, licensesByKey, rootDir, hashMap) {
  let prodCount = 0;
  let excludedCount = 0;
  for (const c of bom.components || []) {
    if (prodKeys.has(componentKey(c))) {
      prodCount++;
      // Clear any generator-assigned scope.  SBOM generators like cdxgen
      // mark most lockfile entries as "optional" because they cannot
      // confirm runtime usage from static analysis alone.  We override
      // with a more accurate signal: transitive walk of package.json
      // "dependencies" (not "devDependencies") across all workspaces.
      // Omitting scope means "required" per the CycloneDX spec.
      delete c.scope;
      enrichLicense(c, licensesByKey, rootDir);
      if (hashMap) enrichHash(c, hashMap);
      enrichEvidence(c);
    } else {
      // Not reachable at runtime — only needed for build, test, or dev.
      c.scope = "excluded";
      excludedCount++;
      enrichLicense(c, licensesByKey, rootDir);
      if (hashMap) enrichHash(c, hashMap);
    }
  }
  return { bom, prodCount, excludedCount };
}

/**
 * Filter the SBOM to production components only, removing dev-only
 * components and pruning the dependency graph.
 * Returns the filtered bom.
 */
export function filterProdOnly(bom, prodKeys, licensesByKey, rootDir, hashMap) {
  const matchingRefs = new Set();
  const filteredComponents = (bom.components || []).filter((c) => {
    if (prodKeys.has(componentKey(c))) {
      matchingRefs.add(c["bom-ref"]);
      delete c.scope;
      enrichLicense(c, licensesByKey, rootDir);
      if (hashMap) enrichHash(c, hashMap);
      enrichEvidence(c);
      return true;
    }
    return false;
  });

  const filteredDeps = (bom.dependencies || [])
    .filter((d) => matchingRefs.has(d.ref))
    .map((d) => ({
      ref: d.ref,
      ...(d.dependsOn
        ? { dependsOn: d.dependsOn.filter((r) => matchingRefs.has(r)) }
        : {}),
    }));

  return {
    ...bom,
    components: filteredComponents,
    dependencies: filteredDeps,
  };
}

// ── CLI ──────────────────────────────────────────────────────────────

const __filename = fileURLToPath(import.meta.url);

function isMainModule() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(__filename);
  } catch {
    return resolve(process.argv[1]) === resolve(__filename);
  }
}

if (isMainModule()) {
  const args = process.argv.slice(2);
  const prodOnlyFlag = args.includes("--prod-only");

  function flagValue(name) {
    const idx = args.indexOf(name);
    return idx !== -1 && args[idx + 1] ? args[idx + 1] : null;
  }

  const flagIndices = new Set();
  for (const flag of ["--project-dir", "-o", "--output"]) {
    const idx = args.indexOf(flag);
    if (idx !== -1) { flagIndices.add(idx); flagIndices.add(idx + 1); }
  }

  const projectDir = resolve(flagValue("--project-dir") || process.cwd());
  const outputFlag = flagValue("-o") || flagValue("--output");

  const positional = args.filter(
    (a, i) => !a.startsWith("--") && !flagIndices.has(i),
  );
  if (positional.length === 0) {
    console.error(
      "Usage: cdx-npm-enrich [options] <bom.cdx.json>\n\n" +
      "Options:\n" +
      "  --project-dir <dir>  Project root (default: cwd)\n" +
      "  -o, --output <file>  Write to file instead of modifying in-place\n" +
      "  --prod-only          Strip dev components instead of marking excluded",
    );
    process.exit(1);
  }
  const sbomPath = resolve(positional[0]);
  const outPath = outputFlag ? resolve(outputFlag) : sbomPath;

  const pkgFiles = discoverWorkspacePackages(projectDir);
  const directProd = collectDirectProdDeps(pkgFiles);
  const allProd = resolveAllProdDeps(directProd, projectDir);

  const prodKeys = new Set(allProd.keys());
  const licensesByKey = new Map();
  for (const [key, info] of allProd) {
    if (info.license) licensesByKey.set(key, info.license);
  }

  const hashMap = parseLocfileChecksums(projectDir);
  const bom = JSON.parse(readFileSync(sbomPath, "utf8"));

  if (prodOnlyFlag) {
    const filtered = filterProdOnly(bom, prodKeys, licensesByKey, projectDir, hashMap);
    writeFileSync(outPath, JSON.stringify(filtered, null, 2));
    const withLicense = filtered.components.filter(
      (c) => c.licenses && c.licenses.length > 0,
    ).length;
    console.log(
      `Filtered SBOM: ${filtered.components.length} components` +
        ` (${withLicense} with licenses),` +
        ` ${filtered.dependencies.length} deps` +
        ` (from ${bom.components?.length ?? 0} total)`,
    );
  } else {
    const { prodCount, excludedCount } = markDevExcluded(
      bom, prodKeys, licensesByKey, projectDir, hashMap,
    );
    writeFileSync(outPath, JSON.stringify(bom, null, 2));
    console.log(
      `SBOM: ${bom.components?.length ?? 0} components` +
        ` (${prodCount} prod, ${excludedCount} excluded),` +
        ` ${bom.dependencies?.length ?? 0} deps`,
    );
  }
}
