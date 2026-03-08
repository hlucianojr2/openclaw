/**
 * Tests for SystemValidator — pre-installation system checks.
 *
 * All OS-level calls (exec, net.createServer) are mocked so tests run
 * deterministically on any platform.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { SystemCheck, SystemValidation } from "../../src/shared/ipc-types.js";

// ─── Mocks ────────────────────────────────────────────────────────────────

// Shared mutable state lets individual tests override the engine detector result.
let mockDetectResult: { variant: string; version: string; running: boolean } =
  { variant: "docker-desktop", version: "27.0.0", running: true };
let mockInstallOptions: { dockerDesktop: boolean; dockerCE: boolean } =
  { dockerDesktop: true, dockerCE: false };

vi.mock("../../src/main/docker/engine-detector.js", () => ({
  EngineDetector: class {
    async detect() { return mockDetectResult; }
    getInstallOptions() { return mockInstallOptions; }
  },
}));

// Mock net.createServer so port-check always succeeds by default
const mockServerClose = vi.fn((cb?: () => void) => { cb?.(); });
const mockServerListen = vi.fn((_port: number, _host: string) => {});
const mockServer = {
  once: vi.fn((event: string, handler: (...args: unknown[]) => void) => {
    if (event === "listening") { setTimeout(handler, 0); }
    return mockServer;
  }),
  close: mockServerClose,
  listen: mockServerListen,
};
vi.mock("node:net", () => ({
  createServer: vi.fn(() => mockServer),
}));

// Mock child_process.exec (used in disk/OS checks)
vi.mock("node:child_process", () => ({
  exec: vi.fn(),
}));

// Mock util.promisify to return a function that resolves with disk info
vi.mock("node:util", () => ({
  promisify: vi.fn((fn: unknown) => {
    if (typeof fn === "function") {
      // Return a function that gives enough disk space by default
      return vi.fn().mockResolvedValue({ stdout: "Filesystem 1K-blocks Used Available\n/ 500000000 100000 400000000 25% /", stderr: "" });
    }
    return fn;
  }),
}));

// ─── Helpers ─────────────────────────────────────────────────────────────

function getCheckByName(validation: SystemValidation, name: string): SystemCheck {
  const check = validation.checks.find((c) => c.name === name);
  if (!check) { throw new Error(`Check "${name}" not found in results`); }
  return check;
}

// ─── Tests ────────────────────────────────────────────────────────────────

describe("SystemValidator.validate()", () => {
  let validator: import("../../src/main/installer/system-validator.js").SystemValidator;

  beforeEach(async () => {
    vi.clearAllMocks();
    // Reset shared engine detector state to healthy defaults
    mockDetectResult = { variant: "docker-desktop", version: "27.0.0", running: true };
    mockInstallOptions = { dockerDesktop: true, dockerCE: false };
    // Reset server mock to trigger "listening" each time
    mockServer.once.mockImplementation((event: string, handler: (...args: unknown[]) => void) => {
      if (event === "listening") { setTimeout(handler, 0); }
      return mockServer;
    });
    const { SystemValidator } = await import("../../src/main/installer/system-validator.js");
    validator = new SystemValidator();
  });

  it("returns a SystemValidation with all expected check names", async () => {
    const result = await validator.validate();
    const names = result.checks.map((c) => c.name);
    expect(names).toContain("Operating System");
    expect(names).toContain("Node.js Runtime");
    expect(names).toContain("Container Engine");
    expect(names).toContain("Available Memory");
    expect(names).toContain("Disk Space");
  });

  it("includes port availability checks", async () => {
    const result = await validator.validate();
    const portChecks = result.checks.filter((c) => c.name.includes("port") || c.name.includes("Port"));
    expect(portChecks.length).toBeGreaterThanOrEqual(2);
  });

  it("sets canProceed=true when no check is fail", async () => {
    const result = await validator.validate();
    expect(result.canProceed).toBe(true);
  });

  it("allPassed=true only when every check is pass (not warn)", async () => {
    const result = await validator.validate();
    const allPass = result.checks.every((c) => c.result === "pass");
    expect(result.allPassed).toBe(allPass);
  });

  it("Node.js check passes for the current runtime (>=22)", async () => {
    const result = await validator.validate();
    const nodeCheck = getCheckByName(result, "Node.js Runtime");
    // Test runs on Node >=22 per engines requirement
    expect(nodeCheck.result).toBe("pass");
  });

  it("Container Engine check passes when Docker is running", async () => {
    const result = await validator.validate();
    const dockerCheck = getCheckByName(result, "Container Engine");
    expect(dockerCheck.result).toBe("pass");
    expect(dockerCheck.message).toContain("Docker Desktop");
  });

  it("Container Engine check fails when Docker is not running", async () => {
    mockDetectResult = { variant: "docker-desktop", version: "", running: false };
    mockInstallOptions = { dockerDesktop: true, dockerCE: false };
    const result = await validator.validate();
    const dockerCheck = getCheckByName(result, "Container Engine");
    expect(dockerCheck.result).toBe("fail");
    expect(dockerCheck.autoFixAvailable).toBe(true);
  });

  it("Container Engine check fail sets autoFixAvailable=false when no install option", async () => {
    mockDetectResult = { variant: "none", version: "", running: false };
    mockInstallOptions = { dockerDesktop: false, dockerCE: false };
    const result = await validator.validate();
    const dockerCheck = getCheckByName(result, "Container Engine");
    expect(dockerCheck.result).toBe("fail");
    expect(dockerCheck.autoFixAvailable).toBe(false);
  });

  it("port check warns when port is in use", async () => {
    // Make the server emit "error" instead of "listening" for the first port
    let callCount = 0;
    mockServer.once.mockImplementation((event: string, handler: (...args: unknown[]) => void) => {
      if (event === "error" && callCount++ === 0) {
        setTimeout(() => handler(new Error("EADDRINUSE")), 0);
      } else if (event === "listening") {
        setTimeout(handler, 0);
      }
      return mockServer;
    });

    const { SystemValidator } = await import("../../src/main/installer/system-validator.js");
    const v = new SystemValidator();
    const result = await v.validate();
    // At least one port check should be warn
    const portChecks = result.checks.filter((c) => c.name.includes("port") || c.name.includes("Port"));
    expect(portChecks.some((c) => c.result === "warn")).toBe(true);
  });

  it("all checks have required fields", async () => {
    const result = await validator.validate();
    for (const check of result.checks) {
      expect(typeof check.name).toBe("string");
      expect(typeof check.description).toBe("string");
      expect(["pass", "warn", "fail"]).toContain(check.result);
      expect(typeof check.message).toBe("string");
      expect(typeof check.autoFixAvailable).toBe("boolean");
    }
  });
});
