/**
 * McpAuditLogger — unit tests.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { vi } from "vitest";

vi.mock("electron", () => ({
  app: {
    getPath: vi.fn(() => tmpdir()),
  },
}));

import { McpAuditLogger } from "../../src/main/mcp/mcp-audit-logger.js";

let tmpDir: string;
let logger: McpAuditLogger;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "occc-mcp-audit-test-"));
  logger = new McpAuditLogger(tmpDir);
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

describe("McpAuditLogger", () => {
  it("starts empty", () => {
    expect(logger.count()).toBe(0);
    expect(logger.query()).toHaveLength(0);
  });

  it("append() stores an entry with id and timestamp", () => {
    const entry = logger.append({
      toolName: "read_file",
      category: "filesystem",
      agentId: "agent-1",
      outcome: "approved",
    });
    expect(entry.id).toHaveLength(16); // 8 bytes hex
    expect(entry.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}/);
    expect(entry.outcome).toBe("approved");
    expect(logger.count()).toBe(1);
  });

  it("query() returns entries most-recent-first", () => {
    logger.append({ toolName: "a", category: "filesystem", agentId: "ag", outcome: "approved" });
    logger.append({ toolName: "b", category: "clipboard", agentId: "ag", outcome: "denied" });

    const results = logger.query();
    // Most recent first
    expect(results[0].toolName).toBe("b");
    expect(results[1].toolName).toBe("a");
  });

  it("query() filters by outcome", () => {
    logger.append({ toolName: "a", category: "filesystem", agentId: "ag", outcome: "approved" });
    logger.append({ toolName: "b", category: "clipboard", agentId: "ag", outcome: "denied" });

    const approved = logger.query({ outcome: "approved" });
    expect(approved).toHaveLength(1);
    expect(approved[0].toolName).toBe("a");

    const denied = logger.query({ outcome: "denied" });
    expect(denied).toHaveLength(1);
    expect(denied[0].toolName).toBe("b");
  });

  it("query() filters by agentId", () => {
    logger.append({ toolName: "a", category: "filesystem", agentId: "agent-1", outcome: "approved" });
    logger.append({ toolName: "b", category: "filesystem", agentId: "agent-2", outcome: "approved" });

    const results = logger.query({ agentId: "agent-1" });
    expect(results).toHaveLength(1);
    expect(results[0].agentId).toBe("agent-1");
  });

  it("query() respects limit", () => {
    for (let i = 0; i < 10; i++) {
      logger.append({ toolName: `tool${i}`, category: "system-info", agentId: "ag", outcome: "approved" });
    }
    const results = logger.query({ limit: 3 });
    expect(results).toHaveLength(3);
  });

  it("countToday() counts entries from today", () => {
    logger.append({ toolName: "a", category: "filesystem", agentId: "ag", outcome: "approved" });
    logger.append({ toolName: "b", category: "filesystem", agentId: "ag", outcome: "denied" });
    logger.append({ toolName: "c", category: "filesystem", agentId: "ag", outcome: "blocked" });

    const counts = logger.countToday();
    expect(counts.approved).toBe(1);
    expect(counts.denied).toBe(1);
    expect(counts.blocked).toBe(1);
    expect(counts.expired).toBe(0);
    expect(counts.error).toBe(0);
  });

  it("persists entries to disk and reloads on construction", () => {
    logger.append({ toolName: "read_file", category: "filesystem", agentId: "ag", outcome: "approved" });
    logger.append({ toolName: "open_url", category: "browser", agentId: "ag", outcome: "blocked" });

    const logger2 = new McpAuditLogger(tmpDir);
    expect(logger2.count()).toBe(2);

    const entries = logger2.query();
    expect(entries.some((e) => e.toolName === "read_file")).toBe(true);
    expect(entries.some((e) => e.toolName === "open_url")).toBe(true);
  });

  it("errorMessage is stored when present", () => {
    logger.append({
      toolName: "write_file",
      category: "filesystem",
      agentId: "ag",
      outcome: "error",
      errorMessage: "Permission denied",
    });
    const results = logger.query();
    expect(results[0].errorMessage).toBe("Permission denied");
  });

  it("query() filters by category", () => {
    logger.append({ toolName: "read_file", category: "filesystem", agentId: "ag", outcome: "approved" });
    logger.append({ toolName: "open_url", category: "browser", agentId: "ag", outcome: "blocked" });

    const fsEntries = logger.query({ category: "filesystem" });
    expect(fsEntries).toHaveLength(1);
    expect(fsEntries[0].toolName).toBe("read_file");
  });
});
