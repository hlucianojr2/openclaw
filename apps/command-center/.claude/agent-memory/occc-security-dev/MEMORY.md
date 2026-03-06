# OCCC Security Dev Agent Memory

## Key Architectural Decisions

### RBAC Enforcement in IPC Layer (Phase 5 finding)
- `requireSkillsWrite` must check BOTH `session.elevated` AND `hasPermission(session.role, "skills:approve")`.
- Elevation alone is not sufficient — an elevated operator still lacks `skills:approve` per the RBAC matrix.
- Pattern: check elevation first (fast fail), then check role permission.
- Reference: `src/main/skills/skills-ipc.ts` and `src/main/auth/auth-ipc.ts` for the canonical pattern.

### Elevation Drop After Mutations (auth-ipc.ts pattern)
- After any sensitive mutation IPC handler completes successfully, call `sessions.dropElevation(token as string)`.
- This makes each elevated mutation a one-shot operation, matching the pattern in `auth-ipc.ts` (AUTH_CREATE_USER, AUTH_UPDATE_ROLE, AUTH_RESET_PASSWORD, AUTH_DELETE_USER, AUTH_ENROLL_BIOMETRIC).

### File Mode Enforcement (POSIX)
- `writeFile(..., { mode: 0o600 })` does NOT chmod pre-existing files on POSIX — it only sets the mode for newly created files.
- After every `writeFile`, add `await chmod(filePath, 0o600)` to enforce the mode unconditionally.
- Both `writeFile` and `chmod` must be imported from `node:fs/promises`.

### RBAC Permission Matrix for Skills (Phase 5)
- `skills:list` — viewer, operator, admin, super-admin
- `skills:install` — admin, super-admin only
- `skills:approve` — admin, super-admin only
- Renderer `canAction` check: `super-admin || admin` only (never operator).

## Test Patterns

### Mocking node:fs/promises in Vitest
- Mock MUST include every export the implementation calls.
- When adding new `node:fs/promises` calls (e.g., `chmod`), update ALL test files that mock this module.
- Pattern: `vi.mock("node:fs/promises", () => ({ writeFile: vi.fn().mockResolvedValue(undefined), chmod: vi.fn().mockResolvedValue(undefined) }))`
- Files with `vi.resetModules()` in `beforeEach` need the mock re-applied inline in each `beforeEach`.

### IPC Handler Test Pattern (config-ipc.test.ts / skills-ipc.test.ts)
- Capture handlers via mock `ipcMain.handle`: `handlers.set(channel, handler)`
- Invoke directly: `handler({}, "token", ...args)`
- Mock `SessionManager` minimally: `{ resolve: vi.fn().mockReturnValue(session), dropElevation: vi.fn() }`
- Mock `rbac.js` with a realistic permission matrix for the roles under test.
- Import the module under test AFTER mocks are set up (top-level `await import(...)`).
- Each test group that needs a different session calls `handlers.clear()` then re-registers.

## File Locations

- RBAC: `src/main/auth/rbac.ts` — `hasPermission(role, permission)`, `Permission` type
- Session Manager: `src/main/auth/session-manager.ts` — `resolve()`, `dropElevation()`, `elevateSession()`
- Skills IPC: `src/main/skills/skills-ipc.ts`
- IPC channels: `src/shared/ipc-types.ts` — `IPC_CHANNELS` object
- Auth IPC (reference pattern): `src/main/auth/auth-ipc.ts`
- Test directory: `test/skills/`, `test/auth/`, `test/config/`

## IPC Channel Names (Skills Phase 5)
- `SKILLS_REQUEST_INSTALL`: `"occc:skills:request-install"` — requires `skills:install` permission
- `SKILLS_GET_ALLOWLIST`: `"occc:skills:get-allowlist"` — read, any session
- `SKILLS_GET_PENDING`: `"occc:skills:get-pending"` — read, any session
- `SKILLS_GET_REQUEST`: `"occc:skills:get-request"` — read, any session
- `SKILLS_APPROVE`: `"occc:skills:approve"` — elevated + `skills:approve`
- `SKILLS_REJECT`: `"occc:skills:reject"` — elevated + `skills:approve`
- `SKILLS_REMOVE_ALLOWLIST`: `"occc:skills:remove-allowlist"` — elevated + `skills:approve`
