# @cyberstamp/cdx-npm-enrich

Enrich [CycloneDX](https://cyclonedx.org/) SBOMs for npm/yarn/pnpm projects with dev/prod dependency scope and missing license data.

> **NOTE:** In an ideal world this utility shouldn't exist. Hopefully, SBOM generators for Node.js will align on a common and standard approach to manifest prod and non-prod dependencies soon.


## Why

CycloneDX SBOM generators for Node.js produce varying levels of scope and license coverage. Some omit scope entirely, others use lockfile heuristics or AST analysis that can misclassify dependencies. License metadata is often incomplete.

This tool post-processes any CycloneDX npm SBOM to ensure:

- **Scope classification**: dev-only dependencies are marked `scope: "excluded"` (not reachable at runtime per the [CycloneDX spec](https://cyclonedx.org/docs/1.6/json/#components_items_scope)), production dependencies have their scope cleared (implied `"required"`)
- **Complete licenses**: components missing license metadata are enriched from `node_modules/*/package.json`

Production vs dev classification is based on transitively walking `package.json` `dependencies` (not `devDependencies`) across all workspaces — a more reliable signal than lockfile-based heuristics or static analysis.

### Generators tested (August 2026)

| Generator | Scope | Licenses | Issues addressed |
|-----------|-------|----------|-----------------|
| [cdxgen](https://github.com/CycloneDX/cdxgen) 12.x | Most components marked `optional`; some `excluded` for type-only imports. `--required-only` can strip non-prod components. Neither mode marks dev deps as `excluded`. | Can resolve licenses by querying public registries (`FETCH_LICENSE=true`); disabled by default due to performance. Does not read from `node_modules/*/package.json`. | Scope reclassified; missing licenses enriched from local `package.json` (fast, offline) |
| [@cyclonedx/yarn-plugin-cyclonedx](https://github.com/CycloneDX/cyclonedx-node-yarn) 3.3 | No scope set. `--prod` can strip dev deps. No option to keep all and mark dev deps as `excluded`. | Resolved from `package.json` in `node_modules` (same approach as this tool). | Scope added |
| [pnpm sbom](https://pnpm.io/cli/sbom) 11.x | No scope set. `--prod` can strip dev deps. No option to keep all and mark dev deps as `excluded`. | Resolved from `package.json` in `node_modules` (same approach as this tool). | Scope added |

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

1. Discovers all workspace packages from `package.json` or `pnpm-workspace.yaml`
2. Collects direct production dependencies (`dependencies`, not `devDependencies`) from each workspace, skipping `workspace:` protocol references
3. Transitively resolves all production dependencies through `node_modules`
4. For each component in the SBOM:
   - **Production**: clears any existing scope (implied `"required"` per CycloneDX spec) and enriches missing license data
   - **Dev-only**: sets `scope: "excluded"` (or removes the component in `--prod-only` mode)

## License

[Apache-2.0](LICENSE)
