/**
 * Tests for SkillAllowlist — in-memory state and persistence contract.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("electron", () => ({
  app: { getPath: vi.fn(() => "/tmp/occc-test") },
}));

// Track writeFile calls without hitting the filesystem
const mockWriteFile = vi.fn().mockResolvedValue(undefined);
vi.mock("node:fs/promises", () => ({ writeFile: mockWriteFile }));

// existsSync returns false by default (no pre-existing file)
const mockExistsSync = vi.fn(() => false);
const mockReadFileSync = vi.fn(() => "{}");
vi.mock("node:fs", () => ({
  existsSync: mockExistsSync,
  readFileSync: mockReadFileSync,
}));

describe("SkillAllowlist", () => {
  let SkillAllowlist: typeof import("../../src/main/skills/skill-allowlist.js").SkillAllowlist;

  beforeEach(async () => {
    vi.clearAllMocks();
    mockExistsSync.mockReturnValue(false);
    const mod = await import("../../src/main/skills/skill-allowlist.js");
    SkillAllowlist = mod.SkillAllowlist;
  });

  it("starts empty when no file exists", () => {
    const al = new SkillAllowlist("/tmp/test");
    expect(al.list()).toHaveLength(0);
    expect(al.has("healthcheck")).toBe(false);
  });

  it("add() stores entry and persists", async () => {
    const al = new SkillAllowlist("/tmp/test");
    await al.add({
      skillId: "healthcheck",
      skillName: "Health Check",
      addedAt: "2026-01-01T00:00:00.000Z",
      addedByUserId: "user-1",
      riskLevel: "low",
    });

    expect(al.has("healthcheck")).toBe(true);
    expect(al.list()).toHaveLength(1);
    expect(mockWriteFile).toHaveBeenCalledOnce();

    const [path, content] = mockWriteFile.mock.calls[0] as [string, string, unknown];
    expect(path).toContain("openclaw-allowlist.json");
    const parsed = JSON.parse(content);
    expect(parsed.entries).toHaveLength(1);
    expect(parsed.entries[0].skillId).toBe("healthcheck");
  });

  it("remove() deletes entry and persists", async () => {
    const al = new SkillAllowlist("/tmp/test");
    await al.add({
      skillId: "summarize",
      skillName: "Summarize",
      addedAt: "2026-01-01T00:00:00.000Z",
      addedByUserId: "user-1",
      riskLevel: "low",
    });

    const removed = await al.remove("summarize");
    expect(removed).toBe(true);
    expect(al.has("summarize")).toBe(false);
    expect(al.list()).toHaveLength(0);
  });

  it("remove() returns false when skill not in allowlist", async () => {
    const al = new SkillAllowlist("/tmp/test");
    const removed = await al.remove("nonexistent");
    expect(removed).toBe(false);
    // No persistence call on no-op remove
    expect(mockWriteFile).not.toHaveBeenCalled();
  });

  it("loads existing entries from file on construction", async () => {
    mockExistsSync.mockReturnValue(true);
    mockReadFileSync.mockReturnValue(JSON.stringify({
      entries: [{
        skillId: "canvas",
        skillName: "Canvas",
        addedAt: "2026-01-01T00:00:00.000Z",
        addedByUserId: "user-1",
        riskLevel: "low",
      }],
    }));

    const al = new SkillAllowlist("/tmp/test");
    expect(al.has("canvas")).toBe(true);
    expect(al.list()).toHaveLength(1);
  });

  it("survives corrupt file content on load", async () => {
    mockExistsSync.mockReturnValue(true);
    mockReadFileSync.mockReturnValue("NOT VALID JSON {{{");
    // Should not throw
    const al = new SkillAllowlist("/tmp/test");
    expect(al.list()).toHaveLength(0);
  });
});
