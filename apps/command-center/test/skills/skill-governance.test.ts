/**
 * Tests for SkillGovernance — approval pipeline logic.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("electron", () => ({
  app: { getPath: vi.fn(() => "/tmp/occc-test") },
}));

const mockWriteFile = vi.fn().mockResolvedValue(undefined);
vi.mock("node:fs/promises", () => ({ writeFile: mockWriteFile, chmod: vi.fn().mockResolvedValue(undefined) }));

vi.mock("node:fs", () => ({
  existsSync: vi.fn(() => false),
  readFileSync: vi.fn(() => "{}"),
}));

// Scanner is unavailable in test environment — governance must handle gracefully
vi.mock("../../../../../src/security/skill-scanner.js", () => {
  throw new Error("Module not found");
});

describe("SkillGovernance — requestInstall", () => {
  let SkillGovernance: typeof import("../../src/main/skills/skill-governance.js").SkillGovernance;

  beforeEach(async () => {
    vi.clearAllMocks();
    vi.resetModules();
    // Re-apply fs mocks after resetModules
    vi.mock("node:fs", () => ({
      existsSync: vi.fn(() => false),
      readFileSync: vi.fn(() => "{}"),
    }));
    vi.mock("node:fs/promises", () => ({ writeFile: vi.fn().mockResolvedValue(undefined), chmod: vi.fn().mockResolvedValue(undefined) }));
    vi.mock("electron", () => ({ app: { getPath: vi.fn(() => "/tmp/occc-test") } }));

    const mod = await import("../../src/main/skills/skill-governance.js");
    SkillGovernance = mod.SkillGovernance;
  });

  it("returns rejected for unknown skill ID", async () => {
    const gov = new SkillGovernance({ dataDir: "/tmp/test" });
    const result = await gov.requestInstall("nonexistent-skill", "user-1");
    expect(result.outcome).toBe("rejected");
    expect(result.message).toContain("nonexistent-skill");
  });

  it("returns approved_immediate for auto-approved skill", async () => {
    const gov = new SkillGovernance({ dataDir: "/tmp/test" });
    const result = await gov.requestInstall("healthcheck", "user-1");
    expect(result.outcome).toBe("approved_immediate");
    expect(result.skillId).toBe("healthcheck");
    expect(gov.getAllowlist()).toHaveLength(1);
  });

  it("returns approved_immediate for already-allowlisted skill", async () => {
    const gov = new SkillGovernance({ dataDir: "/tmp/test" });
    await gov.requestInstall("healthcheck", "user-1");
    // Second request — already on allowlist
    const result = await gov.requestInstall("healthcheck", "user-1");
    expect(result.outcome).toBe("approved_immediate");
    expect(result.message).toContain("already approved");
    expect(gov.getAllowlist()).toHaveLength(1);
  });

  it("returns pending_user_ack for user-ack skill", async () => {
    const gov = new SkillGovernance({ dataDir: "/tmp/test" });
    const result = await gov.requestInstall("github", "user-1");
    expect(result.outcome).toBe("pending_user_ack");
    expect(result.requestId).toBeTruthy();
    expect(gov.getPendingRequests()).toHaveLength(1);
  });

  it("returns pending_admin_review for admin-review skill", async () => {
    const gov = new SkillGovernance({ dataDir: "/tmp/test" });
    const result = await gov.requestInstall("coding-agent", "user-1");
    expect(result.outcome).toBe("pending_admin_review");
    expect(result.requestId).toBeTruthy();
  });
});

describe("SkillGovernance — approve and reject", () => {
  let SkillGovernance: typeof import("../../src/main/skills/skill-governance.js").SkillGovernance;

  beforeEach(async () => {
    vi.clearAllMocks();
    vi.resetModules();
    vi.mock("node:fs", () => ({
      existsSync: vi.fn(() => false),
      readFileSync: vi.fn(() => "{}"),
    }));
    vi.mock("node:fs/promises", () => ({ writeFile: vi.fn().mockResolvedValue(undefined), chmod: vi.fn().mockResolvedValue(undefined) }));
    vi.mock("electron", () => ({ app: { getPath: vi.fn(() => "/tmp/occc-test") } }));

    const mod = await import("../../src/main/skills/skill-governance.js");
    SkillGovernance = mod.SkillGovernance;
  });

  it("approve() adds skill to allowlist and marks request approved", async () => {
    const gov = new SkillGovernance({ dataDir: "/tmp/test" });
    const { requestId } = await gov.requestInstall("github", "user-1");

    const result = await gov.approve(requestId!, "admin-1");
    expect(result.ok).toBe(true);
    expect(gov.getAllowlist()).toHaveLength(1);
    expect(gov.getPendingRequests()).toHaveLength(0);

    const req = gov.getRequest(requestId!);
    expect(req?.status).toBe("approved");
    expect(req?.reviewedByUserId).toBe("admin-1");
  });

  it("approve() returns error for unknown request ID", async () => {
    const gov = new SkillGovernance({ dataDir: "/tmp/test" });
    const result = await gov.approve("nonexistent", "admin-1");
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("not found");
  });

  it("approve() returns error if request already approved", async () => {
    const gov = new SkillGovernance({ dataDir: "/tmp/test" });
    const { requestId } = await gov.requestInstall("github", "user-1");
    await gov.approve(requestId!, "admin-1");
    const result = await gov.approve(requestId!, "admin-1");
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("already");
  });

  it("reject() marks request rejected with reason", async () => {
    const gov = new SkillGovernance({ dataDir: "/tmp/test" });
    const { requestId } = await gov.requestInstall("github", "user-1");

    const result = await gov.reject(requestId!, "admin-1", "Not needed");
    expect(result.ok).toBe(true);
    expect(gov.getPendingRequests()).toHaveLength(0);

    const req = gov.getRequest(requestId!);
    expect(req?.status).toBe("rejected");
    expect(req?.rejectionReason).toBe("Not needed");
  });

  it("reject() works without a reason", async () => {
    const gov = new SkillGovernance({ dataDir: "/tmp/test" });
    const { requestId } = await gov.requestInstall("github", "user-1");
    const result = await gov.reject(requestId!, "admin-1");
    expect(result.ok).toBe(true);
    const req = gov.getRequest(requestId!);
    expect(req?.rejectionReason).toBeUndefined();
  });
});

describe("SkillGovernance — allowlist management", () => {
  let SkillGovernance: typeof import("../../src/main/skills/skill-governance.js").SkillGovernance;

  beforeEach(async () => {
    vi.clearAllMocks();
    vi.resetModules();
    vi.mock("node:fs", () => ({
      existsSync: vi.fn(() => false),
      readFileSync: vi.fn(() => "{}"),
    }));
    vi.mock("node:fs/promises", () => ({ writeFile: vi.fn().mockResolvedValue(undefined), chmod: vi.fn().mockResolvedValue(undefined) }));
    vi.mock("electron", () => ({ app: { getPath: vi.fn(() => "/tmp/occc-test") } }));

    const mod = await import("../../src/main/skills/skill-governance.js");
    SkillGovernance = mod.SkillGovernance;
  });

  it("removeFromAllowlist() removes an approved skill", async () => {
    const gov = new SkillGovernance({ dataDir: "/tmp/test" });
    await gov.requestInstall("healthcheck", "user-1");
    expect(gov.getAllowlist()).toHaveLength(1);

    const result = await gov.removeFromAllowlist("healthcheck");
    expect(result.ok).toBe(true);
    expect(gov.getAllowlist()).toHaveLength(0);
  });

  it("removeFromAllowlist() returns error when skill not on allowlist", async () => {
    const gov = new SkillGovernance({ dataDir: "/tmp/test" });
    const result = await gov.removeFromAllowlist("healthcheck");
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("not in allowlist");
  });

  it("getRequest() returns null for unknown ID", () => {
    const gov = new SkillGovernance({ dataDir: "/tmp/test" });
    expect(gov.getRequest("unknown")).toBeNull();
  });
});
