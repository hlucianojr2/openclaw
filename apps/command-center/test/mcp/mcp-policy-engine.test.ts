/**
 * MCP Policy Engine — unit tests.
 *
 * Tests all policy levels and edge cases for path-constraint and domain-allowlist.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { evaluatePolicy } from "../../src/main/mcp/mcp-policy-engine.js";
import type { McpToolCall } from "../../src/main/mcp/mcp-types.js";
import type { McpPolicyStore } from "../../src/main/mcp/mcp-policy-store.js";
import type { McpPolicy, McpToolCategory, McpApprovalLevel } from "../../src/main/mcp/mcp-types.js";

// Mock fs/promises to control realpath
vi.mock("node:fs/promises", () => ({
  realpath: vi.fn(async (p: string) => p),
}));

import { realpath } from "node:fs/promises";
const realpathMock = vi.mocked(realpath);

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeCall(overrides: Partial<McpToolCall> = {}): McpToolCall {
  return {
    toolName: "read_file",
    category: "filesystem",
    agentId: "agent-1",
    args: { path: "/workspace/file.txt" },
    receivedAt: Date.now(),
    ...overrides,
  };
}

function makeStore(level: McpApprovalLevel, extras: Partial<McpPolicy> = {}): McpPolicyStore {
  const policy: McpPolicy = {
    category: "filesystem",
    level,
    allowedDomains: [],
    workspacePath: "/workspace",
    updatedAt: new Date().toISOString(),
    ...extras,
  };
  return {
    getPolicy: vi.fn((_cat: McpToolCategory) => policy),
    getAllPolicies: vi.fn(() => [policy]),
    setPolicy: vi.fn(),
    addAllowedDomain: vi.fn(),
    removeAllowedDomain: vi.fn(),
  } as unknown as McpPolicyStore;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("evaluatePolicy()", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("auto-approved", () => {
    it("returns auto-approved immediately", async () => {
      const store = makeStore("auto-approved");
      const result = await evaluatePolicy(makeCall({ category: "system-info" }), store);
      expect(result.outcome).toBe("auto-approved");
    });
  });

  describe("per-use", () => {
    it("returns needs-approval", async () => {
      const store = makeStore("per-use");
      const result = await evaluatePolicy(makeCall({ category: "clipboard" }), store);
      expect(result.outcome).toBe("needs-approval");
    });
  });

  describe("blocked", () => {
    it("returns blocked with reason", async () => {
      const store = makeStore("blocked");
      const result = await evaluatePolicy(makeCall(), store);
      expect(result.outcome).toBe("blocked");
      expect(result.reason).toBeTruthy();
    });
  });

  describe("path-constrained", () => {
    it("auto-approves path within workspace", async () => {
      realpathMock.mockResolvedValueOnce("/workspace/file.txt");
      realpathMock.mockResolvedValueOnce("/workspace");

      const store = makeStore("path-constrained", { workspacePath: "/workspace" });
      const call = makeCall({ args: { path: "/workspace/file.txt" } });
      const result = await evaluatePolicy(call, store);
      expect(result.outcome).toBe("auto-approved");
    });

    it("blocks path outside workspace", async () => {
      realpathMock.mockResolvedValueOnce("/etc/passwd");
      realpathMock.mockResolvedValueOnce("/workspace");

      const store = makeStore("path-constrained", { workspacePath: "/workspace" });
      const call = makeCall({ args: { path: "/etc/passwd" } });
      const result = await evaluatePolicy(call, store);
      expect(result.outcome).toBe("blocked");
      expect(result.reason).toMatch(/outside/);
    });

    it("falls back to needs-approval when no workspacePath configured", async () => {
      const store = makeStore("path-constrained", { workspacePath: "" });
      const result = await evaluatePolicy(makeCall(), store);
      expect(result.outcome).toBe("needs-approval");
    });

    it("falls back to needs-approval when no path arg provided", async () => {
      const store = makeStore("path-constrained", { workspacePath: "/workspace" });
      const call = makeCall({ args: {} });
      const result = await evaluatePolicy(call, store);
      expect(result.outcome).toBe("needs-approval");
    });

    it("allows exact workspace path", async () => {
      realpathMock.mockResolvedValueOnce("/workspace");
      realpathMock.mockResolvedValueOnce("/workspace");

      const store = makeStore("path-constrained", { workspacePath: "/workspace" });
      const call = makeCall({ args: { path: "/workspace" } });
      const result = await evaluatePolicy(call, store);
      expect(result.outcome).toBe("auto-approved");
    });
  });

  describe("domain-allowlist", () => {
    it("blocks URL with no allowedDomains", async () => {
      const store = makeStore("domain-allowlist", {
        category: "browser",
        allowedDomains: [],
        workspacePath: "",
      });
      const call = makeCall({ category: "browser", args: { url: "https://example.com" } });
      const result = await evaluatePolicy(call, store);
      expect(result.outcome).toBe("blocked");
    });

    it("auto-approves URL on allowlist", async () => {
      const store = makeStore("domain-allowlist", {
        category: "browser",
        allowedDomains: ["example.com"],
        workspacePath: "",
      });
      const call = makeCall({ category: "browser", args: { url: "https://example.com/path" } });
      const result = await evaluatePolicy(call, store);
      expect(result.outcome).toBe("auto-approved");
    });

    it("auto-approves subdomain of allowlisted domain", async () => {
      const store = makeStore("domain-allowlist", {
        category: "browser",
        allowedDomains: ["example.com"],
        workspacePath: "",
      });
      const call = makeCall({ category: "browser", args: { url: "https://api.example.com/v1" } });
      const result = await evaluatePolicy(call, store);
      expect(result.outcome).toBe("auto-approved");
    });

    it("blocks URL not on allowlist", async () => {
      const store = makeStore("domain-allowlist", {
        category: "browser",
        allowedDomains: ["example.com"],
        workspacePath: "",
      });
      const call = makeCall({ category: "browser", args: { url: "https://evil.com" } });
      const result = await evaluatePolicy(call, store);
      expect(result.outcome).toBe("blocked");
    });

    it("blocks file: URL scheme", async () => {
      const store = makeStore("domain-allowlist", {
        category: "browser",
        allowedDomains: ["example.com"],
        workspacePath: "",
      });
      const call = makeCall({ category: "browser", args: { url: "file:///etc/passwd" } });
      const result = await evaluatePolicy(call, store);
      expect(result.outcome).toBe("blocked");
    });

    it("blocks javascript: URL scheme", async () => {
      const store = makeStore("domain-allowlist", {
        category: "browser",
        allowedDomains: ["example.com"],
        workspacePath: "",
      });
      const call = makeCall({ category: "browser", args: { url: "javascript:alert(1)" } });
      const result = await evaluatePolicy(call, store);
      expect(result.outcome).toBe("blocked");
    });

    it("blocks data: URL scheme", async () => {
      const store = makeStore("domain-allowlist", {
        category: "browser",
        allowedDomains: ["example.com"],
        workspacePath: "",
      });
      const call = makeCall({ category: "browser", args: { url: "data:text/html,<h1>XSS</h1>" } });
      const result = await evaluatePolicy(call, store);
      expect(result.outcome).toBe("blocked");
    });

    it("blocks when no URL provided", async () => {
      const store = makeStore("domain-allowlist", {
        category: "browser",
        allowedDomains: ["example.com"],
        workspacePath: "",
      });
      const call = makeCall({ category: "browser", args: {} });
      const result = await evaluatePolicy(call, store);
      expect(result.outcome).toBe("blocked");
    });

    it("blocks invalid URL format", async () => {
      const store = makeStore("domain-allowlist", {
        category: "browser",
        allowedDomains: ["example.com"],
        workspacePath: "",
      });
      const call = makeCall({ category: "browser", args: { url: "not-a-url" } });
      const result = await evaluatePolicy(call, store);
      expect(result.outcome).toBe("blocked");
    });
  });
});
