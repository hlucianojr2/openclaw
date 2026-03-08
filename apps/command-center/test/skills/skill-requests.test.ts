/**
 * Tests for SkillRequestStore — CRUD and pending-filter logic.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("electron", () => ({
  app: { getPath: vi.fn(() => "/tmp/occc-test") },
}));

const mockWriteFile = vi.fn().mockResolvedValue(undefined);
const mockChmod = vi.fn().mockResolvedValue(undefined);
vi.mock("node:fs/promises", () => ({ writeFile: mockWriteFile, chmod: mockChmod }));

const mockExistsSync = vi.fn(() => false);
const mockReadFileSync = vi.fn(() => "{}");
vi.mock("node:fs", () => ({
  existsSync: mockExistsSync,
  readFileSync: mockReadFileSync,
}));

describe("SkillRequestStore", () => {
  let SkillRequestStore: typeof import("../../src/main/skills/skill-requests.js").SkillRequestStore;

  beforeEach(async () => {
    vi.clearAllMocks();
    mockExistsSync.mockReturnValue(false);
    const mod = await import("../../src/main/skills/skill-requests.js");
    SkillRequestStore = mod.SkillRequestStore;
  });

  it("starts empty when no file exists", () => {
    const store = new SkillRequestStore("/tmp/test");
    expect(store.listPending()).toHaveLength(0);
  });

  it("create() returns a pending request with unique id", () => {
    const store = new SkillRequestStore("/tmp/test");
    const req = store.create({
      skillId: "github",
      skillName: "GitHub",
      riskLevel: "medium",
      approvalLevel: "user-ack",
      requestedByUserId: "user-1",
    });

    expect(req.id).toBeTruthy();
    expect(req.status).toBe("pending");
    expect(req.skillId).toBe("github");
    expect(req.requestedByUserId).toBe("user-1");
  });

  it("save() persists a request update", async () => {
    const store = new SkillRequestStore("/tmp/test");
    const req = store.create({
      skillId: "github",
      skillName: "GitHub",
      riskLevel: "medium",
      approvalLevel: "user-ack",
      requestedByUserId: "user-1",
    });

    req.status = "approved";
    await store.save(req);

    const fetched = store.get(req.id);
    expect(fetched?.status).toBe("approved");
    expect(mockWriteFile).toHaveBeenCalled();
  });

  it("listPending() returns only pending requests", async () => {
    const store = new SkillRequestStore("/tmp/test");
    const r1 = store.create({
      skillId: "github",
      skillName: "GitHub",
      riskLevel: "medium",
      approvalLevel: "user-ack",
      requestedByUserId: "user-1",
    });
    const r2 = store.create({
      skillId: "tmux",
      skillName: "Tmux",
      riskLevel: "high",
      approvalLevel: "admin-review",
      requestedByUserId: "user-1",
    });

    r1.status = "approved";
    await store.save(r1);

    const pending = store.listPending();
    expect(pending).toHaveLength(1);
    expect(pending[0].id).toBe(r2.id);
  });

  it("get() returns undefined for unknown id", () => {
    const store = new SkillRequestStore("/tmp/test");
    expect(store.get("nonexistent-id")).toBeUndefined();
  });

  it("loads existing requests from file on construction", async () => {
    mockExistsSync.mockReturnValue(true);
    mockReadFileSync.mockReturnValue(JSON.stringify({
      requests: [{
        id: "req-123",
        skillId: "github",
        skillName: "GitHub",
        riskLevel: "medium",
        approvalLevel: "user-ack",
        requestedAt: "2026-01-01T00:00:00.000Z",
        requestedByUserId: "user-1",
        status: "pending",
      }],
    }));

    const store = new SkillRequestStore("/tmp/test");
    expect(store.get("req-123")).toBeDefined();
    expect(store.listPending()).toHaveLength(1);
  });

  it("two create() calls produce distinct IDs", () => {
    const store = new SkillRequestStore("/tmp/test");
    const r1 = store.create({ skillId: "a", skillName: "A", riskLevel: "low", approvalLevel: "auto-approved", requestedByUserId: "u" });
    const r2 = store.create({ skillId: "b", skillName: "B", riskLevel: "low", approvalLevel: "auto-approved", requestedByUserId: "u" });
    expect(r1.id).not.toBe(r2.id);
  });
});
