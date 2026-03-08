# OCCC Architect Memory

## Key Files (always read before designing)

- Sprint tracker: `apps/command-center/OCCC_SPRINT_TRACKER.md`
- Agent roadmap: `apps/command-center/OCCC_AGENT_ROADMAP.md`
- Implementation Plan: `Implementation Plan` (repo root)
- IPC types: `apps/command-center/src/shared/ipc-types.ts`
- Main entry: `apps/command-center/src/main/index.ts`
- Preload bridge: `apps/command-center/src/preload/index.ts`
- IPC guards: `apps/command-center/src/main/ipc-guards.ts`
- RBAC: `apps/command-center/src/main/auth/rbac.ts`
- Constants: `apps/command-center/src/shared/constants.ts` — MCP port is `DEFAULT_MCP_BRIDGE_PORT = 18791`

## IPC Patterns (established across phases 1–6)

- Channel naming: `"occc:<domain>:<action>"` — all defined in `IPC_CHANNELS` const in `ipc-types.ts`
- Session guard: `requireSession(token, sessions)` from `ipc-guards.ts`
- Elevated guard: `requireElevatedSession(token, sessions)` — use for approve/policy-write ops
- Domain-specific IPC: register via `register<Domain>IpcHandlers()` function, called from `src/main/index.ts`
- Push events (main→renderer): `BrowserWindow.webContents.send(channel, data)` — channel must be in `IPC_CHANNELS`
- Preload bridge: every new `IPC_CHANNELS` entry needs a typed method in `OcccBridge` interface + preload wiring

## Module Patterns (established)

- Module-specific IPC file: `src/main/<domain>/<domain>-ipc.ts` (see config-ipc.ts, auth-ipc.ts)
- Test files: `test/<domain>/*.test.ts` (colocated by domain, not by src path)
- Dynamic imports: used in config-ipc.ts for schema loading — safe for optional deps
- LOC discipline: split at ~400 lines; policy engine, audit logger, server are natural split points

## Completed Sprint Summaries (for reuse detection)

### Phase 1 (Foundation)

- Docker abstraction: `src/main/docker/` — engine-detector, engine-client, container-manager, compose-orchestrator
- IPC guards: `src/main/ipc-guards.ts` — requireSession, requireElevatedSession, validateStackConfig

### Phase 2 (Auth & RBAC)

- `src/main/auth/` — auth-engine, auth-store, biometric, rbac, session-manager
- Permission type in rbac.ts — extend for MCP: add `"mcp:approve"`, `"mcp:policy-write"` permissions

### Phase 4 (Config)

- `src/main/config/` — config-store, config-ipc, schema-introspector
- Pattern for optional dep dynamic import (see loadSchema())

### Phase 5 (Skill Governance)

- `src/main/skills/` — skill-allowlist, skill-requests, skill-ai-reviewer, skill-governance, skills-ipc
- IPC progress push events via `BrowserWindow.webContents.send`

### Phase 6 (Runtime Monitoring)

- Renderer pages: Dashboard, SessionsPage, LogsPage, SkillsPage already exist
- App.tsx navigation: `type Page = "dashboard"|"installer"|"config"|"users"|"skills"|"sessions"|"logs"|"security"`

## Phase 7 (MCP Bridge) — Design Decisions

- MCP bridge server runs as HTTP/1.1 on `DEFAULT_MCP_BRIDGE_PORT = 18791` (already in constants.ts)
- Express is already a dependency — use it for the MCP HTTP server
- No new npm packages needed for the server itself
- Tool categories: filesystem (workspace-only, path-constrained), clipboard, browser (domain allowlist), system-info (auto-approved), notifications (auto-approved), app-control (per-use)
- Policy engine: in-memory Map + JSON persistence to electron-store
- Audit log: JSON append to electron-store (reuse pattern from Phase 2 auth audit)
- OS notifications: Electron `Notification` API (built-in, no extra dep)
- Approval flow: pending request stored in Map → renderer polls or push event → user decides → response unblocked
- Renderer page: `McpBridgePage` — add to `Page` type union + NAV_ITEMS + App.tsx routing
- See `docs/phase-7-architecture.md` for full design

## File Size Risk Areas

- `src/main/mcp/mcp-server.ts` — keep request routing thin; delegate to tool handlers
- `src/renderer/pages/McpBridgePage.tsx` — split AccessRequestCard + PolicyPanel + AuditLogPanel into separate files if > 350 LOC
