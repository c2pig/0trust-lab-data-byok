# Agent & Contributor Instructions (`0trust-lab-data-byok`)

## Two-Way Global <-> Local Architecture Diagram Sync

This standalone lab repository powers **Lab 7 (`Data Classification, Masking & BYOK Crypto-Shredding` — `/data-byok`)** on [`0trust.dev`](https://github.com/c2pig/0trust.dev/blob/main/docs/ECOSYSTEM_MAP.md).

Whenever you modify code, edge functions, or infrastructure under `src/`, `functions/`, or `infra/`:
1. **Local Sync**: Update [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/diagrams/data_byok_architecture.svg`](docs/diagrams/data_byok_architecture.svg) in the same Pull Request (enforced by [`.github/workflows/diagram-check.yml`](.github/workflows/diagram-check.yml)).
2. **Global Sync**: If the lab's public routes, `STATE_KV` prefixes (`lab7:byok:`), seat descriptors, or cryptographic/DLP contracts change, also update `lab.manifest.json`, `docs/labs/data-byok.md`, `docs/diagrams/data_byok_architecture.svg`, and `src/contracts/labManifest.ts` in [`c2pig/0trust.dev`](https://github.com/c2pig/0trust.dev).

## Always Create PR & Merge

- Never commit directly to `main` or leave completed work unmerged on a local branch.
- Always create a Pull Request from a feature branch and **merge it** once local verification and required CI checks pass.
