/**
 * McpPolicyStore — unit tests.
 *
 * Uses a temp directory so tests do not touch userData.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// We must mock `electron` before importing the store
import { vi } from "vitest";

vi.mock("electron", () => ({
  app: {
    getPath: vi.fn(() => tmpdir()),
  },
}));

import { McpPolicyStore } from "../../src/main/mcp/mcp-policy-store.js";

let tmpDir: string;
let store: McpPolicyStore;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "occc-mcp-test-"));
  store = new McpPolicyStore(tmpDir);
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

describe("McpPolicyStore", () => {
  it("returns default policy for each category", () => {
    const fsPolicy = store.getPolicy("filesystem");
    expect(fsPolicy.category).toBe("filesystem");
    expect(fsPolicy.level).toBe("path-constrained");

    const sysPolicy = store.getPolicy("system-info");
    expect(sysPolicy.level).toBe("auto-approved");

    const browserPolicy = store.getPolicy("browser");
    expect(browserPolicy.level).toBe("domain-allowlist");
    expect(browserPolicy.allowedDomains).toHaveLength(0);

    const clipPolicy = store.getPolicy("clipboard");
    expect(clipPolicy.level).toBe("per-use");

    const notifPolicy = store.getPolicy("notifications");
    expect(notifPolicy.level).toBe("auto-approved");

    const appPolicy = store.getPolicy("app-control");
    expect(appPolicy.level).toBe("per-use");
  });

  it("getAllPolicies() returns all 6 categories", () => {
    const all = store.getAllPolicies();
    expect(all).toHaveLength(6);
    const categories = all.map((p) => p.category).toSorted();
    expect(categories).toEqual([
      "app-control",
      "browser",
      "clipboard",
      "filesystem",
      "notifications",
      "system-info",
    ]);
  });

  it("setPolicy() updates the policy and persists", () => {
    const updated = store.setPolicy("filesystem", { level: "per-use" });
    expect(updated.level).toBe("per-use");
    expect(updated.category).toBe("filesystem");
    expect(updated.updatedAt).toBeTruthy();

    // Reload from disk
    const store2 = new McpPolicyStore(tmpDir);
    expect(store2.getPolicy("filesystem").level).toBe("per-use");
  });

  it("setPolicy() preserves fields not in updates", () => {
    store.setPolicy("filesystem", { workspacePath: "/workspace" });
    const updated = store.setPolicy("filesystem", { level: "per-use" });
    expect(updated.workspacePath).toBe("/workspace");
  });

  it("addAllowedDomain() adds domain to browser policy", () => {
    store.addAllowedDomain("example.com");
    const policy = store.getPolicy("browser");
    expect(policy.allowedDomains).toContain("example.com");
  });

  it("addAllowedDomain() is idempotent", () => {
    store.addAllowedDomain("example.com");
    store.addAllowedDomain("example.com");
    const policy = store.getPolicy("browser");
    expect(policy.allowedDomains.filter((d) => d === "example.com")).toHaveLength(1);
  });

  it("removeAllowedDomain() removes domain from browser policy", () => {
    store.addAllowedDomain("example.com");
    store.addAllowedDomain("other.com");
    store.removeAllowedDomain("example.com");
    const policy = store.getPolicy("browser");
    expect(policy.allowedDomains).not.toContain("example.com");
    expect(policy.allowedDomains).toContain("other.com");
  });

  it("persists to disk and reloads correctly", () => {
    store.setPolicy("clipboard", { level: "auto-approved" });
    store.addAllowedDomain("trusted.com");

    const store2 = new McpPolicyStore(tmpDir);
    expect(store2.getPolicy("clipboard").level).toBe("auto-approved");
    expect(store2.getPolicy("browser").allowedDomains).toContain("trusted.com");
  });

  it("handles corrupted file by resetting to defaults", () => {
    writeFileSync(join(tmpDir, "policies.json"), "{ corrupted json }}", "utf8");
    // New store should recover gracefully
    const store2 = new McpPolicyStore(tmpDir);
    expect(store2.getPolicy("filesystem").level).toBe("path-constrained");
  });
});
