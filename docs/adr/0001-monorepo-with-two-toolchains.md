# 0001. One repository with two toolchains

Status: accepted

## Context

The project combines Python services (simulation, vision, agents, the notary) with TypeScript code that must also run in the browser (the web application, the renderer and the public verifier). The same contracts and cryptographic behavior have to hold in both languages, so changes to them must land together.

## Decision

- One repository with a uv workspace for Python and a pnpm workspace for TypeScript. Shared libraries live in `libs/<name>/{py,ts}` next to their language-neutral fixtures and vectors.
- A thin `Makefile` is the single entry point: `make install`, `make lint`, `make typecheck`, `make test`, `make check`.
- Python 3.13 is the baseline because the machine-learning wheels used later are published for it. Raise it only after confirming those wheels exist for the newer version.
- Node 24 and pnpm are pinned through `.nvmrc` and `packageManager`.
- TypeScript packages are consumed as source with no build step: relative imports include the `.ts` extension and only erasable syntax is used.
- Ruff and Pyright for Python; Biome and `tsc` for TypeScript. Biome replaces ESLint plus Prettier to keep one fast tool.
- Repository rules are tests: English-only sources, no references to private material, no committed secrets.

## Consequences

Contracts and cryptography can be changed once and verified in both languages in one pull request. Two toolchains must be installed locally. Source-only TypeScript packages require every consumer to compile TypeScript, which Vite, Vitest and Node 24 already do.
