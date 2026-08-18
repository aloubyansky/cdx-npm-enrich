# @cyberstamp/cdx-npm-enrich

A post-processing utility that enriches [CycloneDX](https://cyclonedx.org/) SBOMs produced by Node.js SBOM generators. It is not an SBOM generator — it takes an existing SBOM as input, cross-references it against `package.json` dependency declarations and `node_modules` contents (not the lockfile), and improves scope classification, license coverage, and hash placement.

> **NOTE:** In an ideal world this utility shouldn't exist. Hopefully, SBOM generators for Node.js will align on a common and standard approach to manifest prod and non-prod dependencies soon.


## Why

CycloneDX SBOM generators for Node.js produce varying levels of scope and license coverage. Some omit scope entirely, others use lockfile heuristics or AST analysis that can misclassify dependencies. License metadata is often incomplete.

This tool post-processes a generator's output to ensure:

- **Scope classification**: dev-only dependencies are marked `scope: "excluded"` (not reachable at runtime per the [CycloneDX spec](https://cyclonedx.org/docs/1.6/json/#components_items_scope)). Production dependencies reachable only through `optionalDependencies` edges retain `scope: "optional"`. All other production dependencies have their scope cleared (implied `"required"`)
- **Complete licenses**: components missing license metadata are enriched from `node_modules/*/package.json`
- **Hashes**: if a component's `externalReferences[type=distribution]` entry has no hashes, a SHA-512 checksum from the lockfile (`yarn.lock`, `pnpm-lock.yaml`, or `package-lock.json`) is added. Hashes are placed on the distribution external reference per the CycloneDX spec (the hash is of the registry tarball, not the component content itself). Existing distribution hashes are preserved
- **Evidence**: production components receive CycloneDX `evidence.identity` confirming their PURL was verified via `manifest-analysis` (reading `package.json` from `node_modules`). Confidence is set to 0.6 — the top of the [CycloneDX-recommended range](https://github.com/CycloneDX/guides/blob/main/SBOM/en/0x60-Evidence.md) for manifest analysis. This is more conservative than cdxgen's 1.0: a lockfile or `package.json` confirms a package was declared and installed, but does not verify that its contents match a known-good artifact (e.g., via content hash). Existing `evidence.identity` from the upstream SBOM generator is preserved

Production vs dev classification builds the dependency graph reachable from workspace `dependencies` (following `dependencies`, `peerDependencies`, and `optionalDependencies` — never `devDependencies`), then classifies each package based on the edge types through which it was reached. Peer dependencies are gated by the consumer workspace's declaration — see [Peer dependency classification](#peer-dependency-classification) below.

### Generators tested (August 2026)

| Generator | Scope | Licenses | Hashes | Evidence | Issues addressed |
|-----------|-------|----------|--------|----------|-----------------|
| [cdxgen](https://github.com/CycloneDX/cdxgen) 12.x | Most components marked `optional`; some `excluded` for type-only imports. `--required-only` can strip non-prod components. Neither mode marks dev deps as `excluded`. | Can resolve licenses by querying public registries (`FETCH_LICENSE=true`); disabled by default due to performance. Does not read from `node_modules/*/package.json`. | SHA-512 from lockfile on `component.hashes` (spec-incorrect — tarball hash placed at top level) | `manifest-analysis` / lockfile name, confidence 1.0 | Scope reclassified; missing licenses enriched; hashes relocated from `component.hashes` to `externalReferences[type=distribution]` |
| [@cyclonedx/yarn-plugin-cyclonedx](https://github.com/CycloneDX/cyclonedx-node-yarn) 3.3 | No scope set. `--prod` can strip dev deps. No option to keep all and mark dev deps as `excluded`. | Resolved from `package.json` in `node_modules` (same approach as this tool). | Not produced | Not produced | Scope added; hashes enriched from lockfile; evidence added |
| [pnpm sbom](https://pnpm.io/cli/sbom) 11.x | Dev deps marked `excluded` with `cdx:npm:package:development` property; prod deps have no scope set (implied `required`). `--prod` strips dev deps, `--no-optional` strips optional deps. | Resolved from `package.json` in `node_modules` (same approach as this tool). | SHA-512 on `externalReferences[type=distribution]` (spec-correct placement) | Not produced | Evidence added (minimal value-add — pnpm sbom already handles scope, licenses, and hashes correctly) |

## Install

```bash
npm install -g @cyberstamp/cdx-npm-enrich
```

Or run directly with npx:

```bash
npx @cyberstamp/cdx-npm-enrich bom.cdx.json
```

## Usage

```
cdx-npm-enrich [options] <bom.cdx.json>
```

The SBOM file is modified in-place.

### Options

| Option | Description |
|--------|-------------|
| `--project-dir <dir>` | Project root containing `package.json` and `node_modules`. Defaults to the current working directory. |
| `-o, --output <file>` | Write to a new file instead of modifying the input in-place. |
| `--prod-only` | Strip dev-only components and their dependency entries instead of marking them `excluded`. |

### Examples

Enrich an SBOM (mark dev deps as excluded, keep everything):

```bash
cdx-npm-enrich bom.cdx.json
```

Enrich an SBOM for a project in a different directory:

```bash
cdx-npm-enrich --project-dir /path/to/project bom.cdx.json
```

Strip dev dependencies entirely:

```bash
cdx-npm-enrich --prod-only bom.cdx.json
```

## Workspace support

The tool auto-detects the workspace configuration:

- **npm/yarn**: reads the `workspaces` field from `package.json`
- **pnpm**: reads `pnpm-workspace.yaml`

Dependencies are resolved from per-workspace `node_modules` directories, including pnpm's content-addressable `.pnpm` store.

## How it works

1. **Workspace discovery**: finds all workspace packages from `package.json` (`workspaces` field) or `pnpm-workspace.yaml`
2. **Graph construction**: collects direct production dependencies (`dependencies`, not `devDependencies`) from each workspace, skipping `workspace:` protocol references. Transitively walks reachable packages through `node_modules`, following `dependencies`, `peerDependencies`, and `optionalDependencies` at each level — `devDependencies` are never followed. Symlinks are resolved so that pnpm's `.pnpm` store siblings are reachable. For pnpm virtual packages (store entries with `_` in the directory name), sibling entries are scanned to discover implicit peer bindings
3. **Prod/dev classification**: propagates production status through the graph. Regular dependencies and optional dependencies are always production. Packages reachable exclusively through `optionalDependencies` edges (including their transitive children) are marked `optional`. A package reachable through both a required and an optional path is classified as required. Peer dependencies are classified based on how the consuming workspace declared them (see below)
4. **Lockfile parsing**: reads SHA-512 checksums from `yarn.lock`, `pnpm-lock.yaml`, or `package-lock.json`
5. **Enrichment**: adds missing license data, hashes (on `externalReferences[type=distribution]`), and `evidence.identity` to production components. Removes `component.hashes` entries that duplicate distribution tarball hashes
6. **Output**: required production components have their scope cleared (implied `"required"` per CycloneDX spec). Optional-only production components get `scope: "optional"`. Dev-only components get `scope: "excluded"` (or are removed in `--prod-only` mode)

### Peer dependency classification

A `peerDependencies` declaration is neutral — it says "the host must provide this" but doesn't indicate whether the package is needed at runtime or only during development. The **consumer's** declaration determines the classification:

- If a workspace has package A in `dependencies` and A declares a peer dep on B:
  - B in the workspace's `dependencies` → **production** (explicitly declared as runtime)
  - B in the workspace's `devDependencies` (not in `dependencies`) → **dev-only** (consumer signaled it's not needed at runtime)
  - B not declared by the workspace at all → **production** (safe default — the consumer didn't signal dev-only, and A needs B at runtime)

- If A is a **transitive** dependency (not directly in any workspace's `dependencies`), no workspace is the direct consumer of A's peer dep. In this case the peer dep is always followed — the workspace's own `devDependencies` are unrelated to A's runtime needs

- A package reached as dev-only through a peer dep edge can still be production if it's reachable through a regular `dependencies` edge from another production package. Classification never downgrades from prod to dev

## Limitations

- The tool classifies dependencies by walking `package.json` fields, not by analyzing actual code usage. A declared production dependency that is never imported at runtime will still be classified as production
- Peer dependencies and optional dependencies that are not installed are silently skipped — the package manager already warns about missing required peers during install
- For pnpm, implicit peer bindings are discovered by scanning sibling entries in virtual store directories. This relies on pnpm's internal directory naming convention (`_` separator for peer variants)

## License

[Apache-2.0](LICENSE)
