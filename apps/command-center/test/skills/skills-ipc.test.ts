/**
 * Unit tests for Skills IPC handler authorization.
 *
 * Covers:
 *   - No token → write operations rejected with "Unauthorized"
 *   - Valid non-elevated session → write operations rejected with "Elevated session required"
 *   - Operator with elevated token → write operations rejected with "Unauthorized" (WARN-2 fix)
 *   - Viewer → SKILLS_REQUEST_INSTALL rejected with "Unauthorized" (WARN-3 fix)
 *   - Admin + elevated → write operations succeed and elevation is dropped (INFO-2 fix)
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { SessionManager } from "../../src/main/auth/session-manager.js";
import type { AuthSession } from "../../src/shared/ipc-types.js";
import { IPC_CHANNELS } from "../../src/shared/ipc-types.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeSession(overrides: Partial<AuthSession> = {}): AuthSession {
  return {
    userId: "user-1",
    role: "admin",
    authenticatedAt: Date.now(),
    expiresAt: Date.now() + 3_600_000,
    elevated: false,
    ...overrides,
  };
}

function makeMockSessions(
  resolved: AuthSession | null = makeSession(),
): SessionManager & { dropElevation: ReturnType<typeof vi.fn> } {
  return {
    resolve: vi.fn().mockReturnValue(resolved),
    dropElevation: vi.fn(),
  } as unknown as SessionManager & { dropElevation: ReturnType<typeof vi.fn> };
}

// ─── Mock Setup ─────────────────────────────────────────────────────────────

// Capture registered handlers so we can invoke them directly in tests.
const handlers = new Map<string, (...args: unknown[]) => Promise<unknown>>();

vi.mock("electron", () => ({
  ipcMain: {
    handle: vi.fn((channel: string, handler: (...args: unknown[]) => Promise<unknown>) => {
      handlers.set(channel, handler);
    }),
  },
}));

// Mock rbac — mirror the real permission matrix for the roles under test.
vi.mock("../../src/main/auth/rbac.js", () => ({
  hasPermission: vi.fn((role: string, permission: string): boolean => {
    const perms: Record<string, string[]> = {
      "super-admin": ["skills:list", "skills:install", "skills:approve"],
      "admin":       ["skills:list", "skills:install", "skills:approve"],
      "operator":    ["skills:list"],
      "viewer":      ["skills:list"],
    };
    return perms[role]?.includes(permission) ?? false;
  }),
}));

// Mock SkillGovernance — we only care about auth guard behavior, not governance logic.
const mockApprove = vi.fn().mockResolvedValue({ ok: true });
const mockReject = vi.fn().mockResolvedValue({ ok: true });
const mockRemoveFromAllowlist = vi.fn().mockResolvedValue({ ok: true });
const mockRequestInstall = vi.fn().mockResolvedValue({
  outcome: "approved_immediate",
  skillId: "healthcheck",
  message: "Approved.",
});
const mockGetAllowlist = vi.fn().mockReturnValue([]);
const mockGetPending = vi.fn().mockReturnValue([]);
const mockGetRequest = vi.fn().mockReturnValue(null);

vi.mock("../../src/main/skills/skill-governance.js", () => ({
  SkillGovernance: class MockSkillGovernance {
    approve = mockApprove;
    reject = mockReject;
    removeFromAllowlist = mockRemoveFromAllowlist;
    requestInstall = mockRequestInstall;
    getAllowlist = mockGetAllowlist;
    getPendingRequests = mockGetPending;
    getRequest = mockGetRequest;
  },
}));

// ─── Import After Mocks ──────────────────────────────────────────────────────

const { registerSkillsIpcHandlers } = await import("../../src/main/skills/skills-ipc.js");
const { SkillGovernance } = await import("../../src/main/skills/skill-governance.js");

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("registerSkillsIpcHandlers() — authorization", () => {
  let sessions: ReturnType<typeof makeMockSessions>;
  let governance: InstanceType<typeof SkillGovernance>;

  beforeEach(() => {
    handlers.clear();
    mockApprove.mockClear();
    mockReject.mockClear();
    mockRemoveFromAllowlist.mockClear();
    mockRequestInstall.mockClear();

    sessions = makeMockSessions(makeSession({ elevated: true, role: "admin" }));
    governance = new SkillGovernance();
    registerSkillsIpcHandlers(sessions, governance);
  });

  // ─── Channel Registration ──────────────────────────────────────────

  it("registers all expected skill IPC channels", () => {
    const expected = [
      IPC_CHANNELS.SKILLS_REQUEST_INSTALL,
      IPC_CHANNELS.SKILLS_GET_ALLOWLIST,
      IPC_CHANNELS.SKILLS_GET_PENDING,
      IPC_CHANNELS.SKILLS_GET_REQUEST,
      IPC_CHANNELS.SKILLS_APPROVE,
      IPC_CHANNELS.SKILLS_REJECT,
      IPC_CHANNELS.SKILLS_REMOVE_ALLOWLIST,
    ];
    for (const ch of expected) {
      expect(handlers.has(ch), `Handler for ${ch} should be registered`).toBe(true);
    }
  });

  // ─── No Token ─────────────────────────────────────────────────────

  describe("no token (null/undefined)", () => {
    beforeEach(() => {
      sessions = makeMockSessions(null);
      handlers.clear();
      registerSkillsIpcHandlers(sessions, governance);
    });

    it("SKILLS_APPROVE rejects with Unauthorized", async () => {
      const handler = handlers.get(IPC_CHANNELS.SKILLS_APPROVE)!;
      await expect(handler({}, null, "req-1")).rejects.toThrow("Unauthorized");
    });

    it("SKILLS_REJECT rejects with Unauthorized", async () => {
      const handler = handlers.get(IPC_CHANNELS.SKILLS_REJECT)!;
      await expect(handler({}, null, "req-1", "reason")).rejects.toThrow("Unauthorized");
    });

    it("SKILLS_REMOVE_ALLOWLIST rejects with Unauthorized", async () => {
      const handler = handlers.get(IPC_CHANNELS.SKILLS_REMOVE_ALLOWLIST)!;
      await expect(handler({}, null, "healthcheck")).rejects.toThrow("Unauthorized");
    });

    it("SKILLS_REQUEST_INSTALL rejects with Unauthorized", async () => {
      const handler = handlers.get(IPC_CHANNELS.SKILLS_REQUEST_INSTALL)!;
      await expect(handler({}, null, "healthcheck")).rejects.toThrow("Unauthorized");
    });
  });

  // ─── Valid Non-Elevated Token ──────────────────────────────────────

  describe("valid non-elevated admin token → write operations rejected", () => {
    beforeEach(() => {
      sessions = makeMockSessions(makeSession({ role: "admin", elevated: false }));
      handlers.clear();
      registerSkillsIpcHandlers(sessions, governance);
    });

    it("SKILLS_APPROVE rejects with 'Elevated session required'", async () => {
      const handler = handlers.get(IPC_CHANNELS.SKILLS_APPROVE)!;
      await expect(handler({}, "tok", "req-1")).rejects.toThrow("Elevated session required");
    });

    it("SKILLS_REJECT rejects with 'Elevated session required'", async () => {
      const handler = handlers.get(IPC_CHANNELS.SKILLS_REJECT)!;
      await expect(handler({}, "tok", "req-1", "reason")).rejects.toThrow("Elevated session required");
    });

    it("SKILLS_REMOVE_ALLOWLIST rejects with 'Elevated session required'", async () => {
      const handler = handlers.get(IPC_CHANNELS.SKILLS_REMOVE_ALLOWLIST)!;
      await expect(handler({}, "tok", "healthcheck")).rejects.toThrow("Elevated session required");
    });

    it("SKILLS_REQUEST_INSTALL succeeds (only needs skills:install, not elevation)", async () => {
      const handler = handlers.get(IPC_CHANNELS.SKILLS_REQUEST_INSTALL)!;
      // Non-elevated admin does have skills:install — should succeed
      const result = await handler({}, "tok", "healthcheck");
      expect(result).toMatchObject({ outcome: "approved_immediate" });
    });
  });

  // ─── WARN-2: Operator With Elevated Token ──────────────────────────

  describe("operator with elevated token → write operations rejected (WARN-2)", () => {
    beforeEach(() => {
      sessions = makeMockSessions(makeSession({ role: "operator", elevated: true }));
      handlers.clear();
      registerSkillsIpcHandlers(sessions, governance);
    });

    it("SKILLS_APPROVE rejects with Unauthorized", async () => {
      const handler = handlers.get(IPC_CHANNELS.SKILLS_APPROVE)!;
      await expect(handler({}, "tok", "req-1")).rejects.toThrow("Unauthorized");
    });

    it("SKILLS_REJECT rejects with Unauthorized", async () => {
      const handler = handlers.get(IPC_CHANNELS.SKILLS_REJECT)!;
      await expect(handler({}, "tok", "req-1", "reason")).rejects.toThrow("Unauthorized");
    });

    it("SKILLS_REMOVE_ALLOWLIST rejects with Unauthorized", async () => {
      const handler = handlers.get(IPC_CHANNELS.SKILLS_REMOVE_ALLOWLIST)!;
      await expect(handler({}, "tok", "healthcheck")).rejects.toThrow("Unauthorized");
    });
  });

  // ─── WARN-3: Viewer → SKILLS_REQUEST_INSTALL ──────────────────────

  describe("viewer role → SKILLS_REQUEST_INSTALL rejected (WARN-3)", () => {
    beforeEach(() => {
      sessions = makeMockSessions(makeSession({ role: "viewer", elevated: false }));
      handlers.clear();
      registerSkillsIpcHandlers(sessions, governance);
    });

    it("SKILLS_REQUEST_INSTALL rejects with Unauthorized", async () => {
      const handler = handlers.get(IPC_CHANNELS.SKILLS_REQUEST_INSTALL)!;
      await expect(handler({}, "tok", "healthcheck")).rejects.toThrow("Unauthorized");
    });
  });

  // ─── WARN-3: Operator → SKILLS_REQUEST_INSTALL ────────────────────

  describe("operator role → SKILLS_REQUEST_INSTALL rejected (WARN-3)", () => {
    beforeEach(() => {
      sessions = makeMockSessions(makeSession({ role: "operator", elevated: false }));
      handlers.clear();
      registerSkillsIpcHandlers(sessions, governance);
    });

    it("SKILLS_REQUEST_INSTALL rejects with Unauthorized", async () => {
      const handler = handlers.get(IPC_CHANNELS.SKILLS_REQUEST_INSTALL)!;
      await expect(handler({}, "tok", "healthcheck")).rejects.toThrow("Unauthorized");
    });
  });

  // ─── Valid Admin + Elevated → Success + Elevation Drop ─────────────

  describe("admin with elevated token → write operations succeed (INFO-2)", () => {
    it("SKILLS_APPROVE succeeds and drops elevation", async () => {
      const handler = handlers.get(IPC_CHANNELS.SKILLS_APPROVE)!;
      const result = await handler({}, "tok", "req-1");
      expect(result).toMatchObject({ ok: true });
      expect(sessions.dropElevation).toHaveBeenCalledWith("tok");
    });

    it("SKILLS_REJECT succeeds and drops elevation", async () => {
      const handler = handlers.get(IPC_CHANNELS.SKILLS_REJECT)!;
      const result = await handler({}, "tok", "req-1", "reason");
      expect(result).toMatchObject({ ok: true });
      expect(sessions.dropElevation).toHaveBeenCalledWith("tok");
    });

    it("SKILLS_REMOVE_ALLOWLIST succeeds and drops elevation", async () => {
      const handler = handlers.get(IPC_CHANNELS.SKILLS_REMOVE_ALLOWLIST)!;
      const result = await handler({}, "tok", "healthcheck");
      expect(result).toMatchObject({ ok: true });
      expect(sessions.dropElevation).toHaveBeenCalledWith("tok");
    });

    it("SKILLS_REQUEST_INSTALL succeeds for admin", async () => {
      const handler = handlers.get(IPC_CHANNELS.SKILLS_REQUEST_INSTALL)!;
      const result = await handler({}, "tok", "healthcheck");
      expect(result).toMatchObject({ outcome: "approved_immediate" });
    });
  });

  // ─── Super-admin + Elevated → Success ──────────────────────────────

  describe("super-admin with elevated token → write operations succeed", () => {
    beforeEach(() => {
      sessions = makeMockSessions(makeSession({ role: "super-admin", elevated: true }));
      handlers.clear();
      registerSkillsIpcHandlers(sessions, governance);
    });

    it("SKILLS_APPROVE succeeds and drops elevation", async () => {
      const handler = handlers.get(IPC_CHANNELS.SKILLS_APPROVE)!;
      const result = await handler({}, "tok", "req-1");
      expect(result).toMatchObject({ ok: true });
      expect(sessions.dropElevation).toHaveBeenCalledWith("tok");
    });

    it("SKILLS_REQUEST_INSTALL succeeds for super-admin", async () => {
      const handler = handlers.get(IPC_CHANNELS.SKILLS_REQUEST_INSTALL)!;
      const result = await handler({}, "tok", "healthcheck");
      expect(result).toMatchObject({ outcome: "approved_immediate" });
    });
  });

  // ─── Read-Only Operations — Any Valid Session ──────────────────────

  describe("read-only operations — any valid session", () => {
    it("SKILLS_GET_ALLOWLIST returns allowlist for operator", async () => {
      sessions = makeMockSessions(makeSession({ role: "operator", elevated: false }));
      handlers.clear();
      registerSkillsIpcHandlers(sessions, governance);

      const handler = handlers.get(IPC_CHANNELS.SKILLS_GET_ALLOWLIST)!;
      const result = await handler({}, "tok");
      expect(Array.isArray(result)).toBe(true);
    });

    it("SKILLS_GET_PENDING returns pending list for viewer", async () => {
      sessions = makeMockSessions(makeSession({ role: "viewer", elevated: false }));
      handlers.clear();
      registerSkillsIpcHandlers(sessions, governance);

      const handler = handlers.get(IPC_CHANNELS.SKILLS_GET_PENDING)!;
      const result = await handler({}, "tok");
      expect(Array.isArray(result)).toBe(true);
    });

    it("SKILLS_GET_REQUEST returns null for unknown ID", async () => {
      const handler = handlers.get(IPC_CHANNELS.SKILLS_GET_REQUEST)!;
      const result = await handler({}, "tok", "unknown-id");
      expect(result).toBeNull();
    });
  });
});
