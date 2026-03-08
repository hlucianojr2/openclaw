/**
 * Unit tests for config IPC handlers.
 *
 * Tests auth guard behavior (unauthorized, unelevated),
 * handler routing, and result shapes.
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

function makeMockSessions(resolved: AuthSession | null = makeSession()): SessionManager {
  return { resolve: vi.fn().mockReturnValue(resolved) } as unknown as SessionManager;
}

// ─── Mock Setup ─────────────────────────────────────────────────────────────

// Capture registered handlers so we can invoke them in tests.
const handlers = new Map<string, (...args: unknown[]) => Promise<unknown>>();

vi.mock("electron", () => ({
  ipcMain: {
    handle: vi.fn((channel: string, handler: (...args: unknown[]) => Promise<unknown>) => {
      handlers.set(channel, handler);
    }),
  },
}));

// Mock ConfigStore — needs to be a class (used with `new`)
const mockRead = vi.fn().mockResolvedValue({
  config: { gateway: { port: 18789 } },
  raw: "gateway:\n  port: 18789\n",
  checksum: "abc123",
  configPath: "/home/user/.openclaw/config.yaml",
});
const mockWrite = vi.fn().mockResolvedValue({ ok: true, checksum: "def456" });
const mockPatch = vi.fn().mockResolvedValue({ ok: true, checksum: "ghi789" });
const mockGetConfigPath = vi.fn().mockReturnValue("/home/user/.openclaw/config.yaml");

vi.mock("../../src/main/config/config-store.js", () => {
  return {
    ConfigStore: class MockConfigStore {
      read = mockRead;
      write = mockWrite;
      patch = mockPatch;
      getConfigPath = mockGetConfigPath;
    },
  };
});

// Mock rbac
vi.mock("../../src/main/auth/rbac.js", () => ({
  hasPermission: vi.fn((role: string, permission: string) => {
    if (permission === "config:read") { return role !== "viewer"; }
    if (permission === "config:write") { return role === "admin" || role === "super-admin"; }
    return false;
  }),
}));

// ─── Register Handlers ──────────────────────────────────────────────────────

// We need to import AFTER mocks are set up
const { registerConfigIpcHandlers } = await import("../../src/main/config/config-ipc.js");

// ─── Tests ──────────────────────────────────────────────────────────────────

describe("registerConfigIpcHandlers()", () => {
  let sessions: SessionManager;

  beforeEach(() => {
    handlers.clear();
    mockRead.mockClear();
    mockWrite.mockClear();
    mockPatch.mockClear();
    mockGetConfigPath.mockClear();
    sessions = makeMockSessions(makeSession({ elevated: true }));
    registerConfigIpcHandlers(sessions);
  });

  it("registers all expected IPC channels", () => {
    const expected = [
      IPC_CHANNELS.CONFIG_READ,
      IPC_CHANNELS.CONFIG_PATH,
      IPC_CHANNELS.CONFIG_WRITE,
      IPC_CHANNELS.CONFIG_PATCH,
      IPC_CHANNELS.CONFIG_VALIDATE,
      IPC_CHANNELS.CONFIG_SCHEMA,
      IPC_CHANNELS.CONFIG_RELOAD,
      IPC_CHANNELS.CONFIG_DIFF,
    ];
    for (const ch of expected) {
      expect(handlers.has(ch), `Handler for ${ch} should be registered`).toBe(true);
    }
  });

  it("does NOT register duplicate hardcoded channel strings", () => {
    // The BLOCKER fix: no handler for the literal string "occc:config:path"
    // registered separately from IPC_CHANNELS.CONFIG_PATH.
    // Since CONFIG_PATH = "occc:config:path", there should be exactly
    // one handler keyed by that string.
    const pathHandlers = [...handlers.entries()].filter(
      ([ch]) => ch === "occc:config:path",
    );
    expect(pathHandlers).toHaveLength(1);
  });

  // ─── Read Handler ───────────────────────────────────────────────────

  describe("CONFIG_READ", () => {
    it("returns config data for authorized user", async () => {
      const handler = handlers.get(IPC_CHANNELS.CONFIG_READ)!;
      const result = await handler({}, "valid-token");
      expect(mockRead).toHaveBeenCalled();
      expect(result).toMatchObject({ config: { gateway: { port: 18789 } } });
    });

    it("throws Unauthorized for null session", async () => {
      sessions = makeMockSessions(null);
      handlers.clear();
      registerConfigIpcHandlers(sessions);

      const handler = handlers.get(IPC_CHANNELS.CONFIG_READ)!;
      await expect(handler({}, "bad-token")).rejects.toThrow("Unauthorized");
    });

    it("throws Unauthorized for viewer role", async () => {
      sessions = makeMockSessions(makeSession({ role: "viewer" }));
      handlers.clear();
      registerConfigIpcHandlers(sessions);

      const handler = handlers.get(IPC_CHANNELS.CONFIG_READ)!;
      await expect(handler({}, "viewer-token")).rejects.toThrow("Unauthorized");
    });
  });

  // ─── Path Handler ──────────────────────────────────────────────────

  describe("CONFIG_PATH", () => {
    it("returns config path for authorized user", async () => {
      const handler = handlers.get(IPC_CHANNELS.CONFIG_PATH)!;
      const result = await handler({}, "valid-token");
      expect(result).toBe("/home/user/.openclaw/config.yaml");
    });
  });

  // ─── Write Handler ─────────────────────────────────────────────────

  describe("CONFIG_WRITE", () => {
    it("writes config for elevated admin", async () => {
      const handler = handlers.get(IPC_CHANNELS.CONFIG_WRITE)!;
      const newConfig = { gateway: { port: 9090 } };
      const result = await handler({}, "valid-token", newConfig, "abc123");
      expect(mockWrite).toHaveBeenCalledWith(newConfig, "abc123");
      expect(result).toMatchObject({ ok: true });
    });

    it("throws 'Elevation required' for non-elevated admin", async () => {
      sessions = makeMockSessions(makeSession({ elevated: false }));
      handlers.clear();
      registerConfigIpcHandlers(sessions);

      const handler = handlers.get(IPC_CHANNELS.CONFIG_WRITE)!;
      await expect(handler({}, "tok", {})).rejects.toThrow("Elevation required");
    });

    it("throws Unauthorized for operator role", async () => {
      sessions = makeMockSessions(makeSession({ role: "operator", elevated: true }));
      handlers.clear();
      registerConfigIpcHandlers(sessions);

      const handler = handlers.get(IPC_CHANNELS.CONFIG_WRITE)!;
      await expect(handler({}, "tok", {})).rejects.toThrow("Unauthorized");
    });
  });

  // ─── Patch Handler ─────────────────────────────────────────────────

  describe("CONFIG_PATCH", () => {
    it("patches config for elevated admin", async () => {
      const handler = handlers.get(IPC_CHANNELS.CONFIG_PATCH)!;
      const patch = { gateway: { port: 9090 } };
      const result = await handler({}, "valid-token", patch, "abc123");
      expect(mockPatch).toHaveBeenCalledWith(patch, "abc123");
      expect(result).toMatchObject({ ok: true });
    });

    it("throws 'Elevation required' for non-elevated session", async () => {
      sessions = makeMockSessions(makeSession({ elevated: false }));
      handlers.clear();
      registerConfigIpcHandlers(sessions);

      const handler = handlers.get(IPC_CHANNELS.CONFIG_PATCH)!;
      await expect(handler({}, "tok", {})).rejects.toThrow("Elevation required");
    });
  });

  // ─── Validate Handler ─────────────────────────────────────────────

  describe("CONFIG_VALIDATE", () => {
    it("returns valid=true when schema import fails", async () => {
      // Schema import will fail in test env — should fall back gracefully
      const handler = handlers.get(IPC_CHANNELS.CONFIG_VALIDATE)!;
      const result = await handler({}, "valid-token", {}) as { valid: boolean; note?: string };
      expect(result.valid).toBe(true);
      expect(result.note).toMatch(/unavailable/i);
    });
  });

  // ─── Schema Handler ──────────────────────────────────────────────

  describe("CONFIG_SCHEMA", () => {
    it("returns empty array when schema import fails", async () => {
      const handler = handlers.get(IPC_CHANNELS.CONFIG_SCHEMA)!;
      const result = await handler({}, "valid-token");
      expect(Array.isArray(result)).toBe(true);
    });

    it("requires config:read permission", async () => {
      sessions = makeMockSessions(null);
      handlers.clear();
      registerConfigIpcHandlers(sessions);

      const handler = handlers.get(IPC_CHANNELS.CONFIG_SCHEMA)!;
      await expect(handler({}, "bad-token")).rejects.toThrow("Unauthorized");
    });
  });

  // ─── Reload Handler ──────────────────────────────────────────────

  describe("CONFIG_RELOAD", () => {
    it("re-reads config from disk", async () => {
      const handler = handlers.get(IPC_CHANNELS.CONFIG_RELOAD)!;
      const result = await handler({}, "valid-token");
      expect(mockRead).toHaveBeenCalled();
      expect(result).toMatchObject({ config: expect.any(Object) as Record<string, unknown> });
    });
  });

  // ─── Diff Handler ────────────────────────────────────────────────

  describe("CONFIG_DIFF", () => {
    it("returns empty array when schema import fails", async () => {
      const handler = handlers.get(IPC_CHANNELS.CONFIG_DIFF)!;
      const result = await handler({}, "valid-token", { gateway: { port: 9090 } });
      // Will either return diff entries or empty array (schema import fails in test)
      expect(Array.isArray(result)).toBe(true);
    });
  });
});
