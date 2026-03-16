# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> For the main OpenClaw CLI project, read `AGENTS.md` — it contains complete guidance on commands, conventions, release workflow, and multi-agent safety rules. This file adds guidance for the **OpenClaw Command Center (OCCC)** Electron app in `apps/command-center/`.

---

## OpenClaw Command Center (`apps/command-center/`)

OCCC is an Electron desktop app with a React + Vite renderer, built on an 11-sprint roadmap tracked in `OCCC_SPRINT_TRACKER.md`. All commands below run from `apps/command-center/` unless noted.

### Commands

```bash
pnpm start           # Dev mode (Electron Forge + Vite HMR)
pnpm test            # Vitest unit tests
pnpm lint            # Oxlint
npx tsc --noEmit     # TypeScript type-check (filter root errors: grep -v "^../../")
```

Run a single test file:

```bash
pnpm vitest run test/skills/skill-governance.test.ts
```

### Architecture

OCCC follows Electron's process boundary strictly:

```
src/
  main/       — Node.js main process (IPC handlers, business logic)
    auth/     — Auth engine, RBAC, session manager, biometric, TOTP
    config/   — Config store, schema introspector, config IPC
    docker/   — Dockerode abstraction (engine-client, container/image/network/volume managers, compose orchestrator)
    installer/— System validator, wizard engine, GitHub setup, voice guide, skill/channel catalogs
    skills/   — Skill governance pipeline, allowlist, AI reviewer, IPC handlers
  preload/    — Typed IPC bridge exposed as `window.occc`
  renderer/   — React app (React Router, no Node.js imports allowed)
    pages/    — Route-level pages (Dashboard, Login, installer/, config/, skills/, users/)
    components/ — Shared components (ElevateModal, etc.)
  shared/
    ipc-types.ts  — Single source of truth for all IPC types + OcccBridge interface
    constants.ts
```

**The IPC contract**: `src/shared/ipc-types.ts` defines every type passed across the process boundary and the `IPC_CHANNELS` constant map. When adding a new channel, update both `ipc-types.ts` and the preload.

**Renderer rule**: Renderer code must never import Node.js modules. All main-process capabilities are accessed through `window.occc` (the `OcccBridge`). Violating this breaks sandbox security.

### Key Conventions (OCCC-specific)

- TypeScript ESM; use `.js` extensions on local imports, `import type` for type-only imports
- No `any` — strict TypeScript throughout
- Files under ~700 LOC; security-related files under ~500 LOC
- Commits: use `scripts/committer "<msg>" <file...>` from repo root — never raw `git add`/`git commit`
- Tests live in `test/` (not colocated in `src/`); coverage threshold is 70% (lines/branches/functions/statements)
- Electron config: `contextIsolation: true`, `sandbox: true` — required for security model
- `window.occc.invoke()` is deprecated dev scaffolding — always add a typed `OcccBridge` method instead

### Sprint Tracker

The sprint tracker at `apps/command-center/OCCC_SPRINT_TRACKER.md` is the authoritative source for sprint status. Agent assignments are in `apps/command-center/OCCC_AGENT_ROADMAP.md`. OCCC-specific agents live in `.github/agents/occc-*.agent.md`.
