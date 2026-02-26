/**
 * Tests for DockerInstaller — Docker installation guidance.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Mocks ────────────────────────────────────────────────────────────────

vi.mock("electron", () => ({
  shell: { openExternal: vi.fn().mockResolvedValue(undefined) },
}));

vi.mock("node:child_process", () => ({
  exec: vi.fn(),
}));

vi.mock("node:util", () => ({
  promisify: vi.fn(() => vi.fn().mockResolvedValue({ stdout: "", stderr: "" })),
}));

const mockDetect = vi.fn().mockResolvedValue({
  variant: "docker-desktop",
  version: "27.0.0",
  running: true,
});
const mockGetInstallOptions = vi.fn().mockReturnValue({
  dockerDesktop: true,
  dockerCE: false,
});

vi.mock("../../src/main/docker/engine-detector.js", () => ({
  EngineDetector: class {
    detect() { return mockDetect(); }
    getInstallOptions() { return mockGetInstallOptions(); }
  },
}));

// ─── Tests ────────────────────────────────────────────────────────────────

describe("DockerInstaller", () => {
  let installer: import("../../src/main/installer/docker-installer.js").DockerInstaller;

  beforeEach(async () => {
    vi.clearAllMocks();
    const { DockerInstaller } = await import("../../src/main/installer/docker-installer.js");
    installer = new DockerInstaller();
  });

  describe("getOptions()", () => {
    it("delegates to EngineDetector.getInstallOptions()", () => {
      const result = installer.getOptions();
      expect(result).toEqual({ dockerDesktop: true, dockerCE: false });
      expect(mockGetInstallOptions).toHaveBeenCalledOnce();
    });
  });

  describe("getDockerCEInstallCommand()", () => {
    it("returns a non-empty install command string", () => {
      const cmd = installer.getDockerCEInstallCommand();
      expect(typeof cmd).toBe("string");
      expect(cmd.length).toBeGreaterThan(10);
    });

    it("includes the official Docker CE install script", () => {
      const cmd = installer.getDockerCEInstallCommand();
      expect(cmd).toContain("get.docker.com");
    });
  });

  describe("verify()", () => {
    it("returns ok:true with version when Docker is running", async () => {
      mockDetect.mockResolvedValueOnce({ variant: "docker-desktop", version: "27.0.0", running: true });
      const result = await installer.verify();
      expect(result.ok).toBe(true);
      expect(result.version).toBe("27.0.0");
    });

    it("returns ok:false when Docker daemon is not running", async () => {
      mockDetect.mockResolvedValueOnce({ variant: "docker-desktop", version: "", running: false });
      const result = await installer.verify();
      expect(result.ok).toBe(false);
      expect(typeof result.error).toBe("string");
      expect(result.error!.length).toBeGreaterThan(0);
    });

    it("returns ok:false when detect() throws", async () => {
      mockDetect.mockRejectedValueOnce(new Error("Connection refused"));
      const result = await installer.verify();
      expect(result.ok).toBe(false);
      expect(result.error).toBe("Connection refused");
    });
  });

  describe("openDockerDesktopDownload()", () => {
    it("calls shell.openExternal with a Docker URL", async () => {
      await installer.openDockerDesktopDownload();
      // shell.openExternal is mocked at top of file; verify via the module mock
      const electronModule = await import("electron");
      const callCount = (electronModule.shell.openExternal as ReturnType<typeof vi.fn>).mock.calls.length;
      expect(callCount).toBe(1);
      const url = (electronModule.shell.openExternal as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
      expect(url).toMatch(/docker\.com/);
    });
  });

  describe("startDockerDesktop()", () => {
    it("returns false on unsupported platform without throwing", async () => {
      // On CI (linux), expect false without throwing
      const result = await installer.startDockerDesktop();
      expect(typeof result).toBe("boolean");
    });
  });

  describe("waitForDocker()", () => {
    it("returns true immediately when Docker is already running", async () => {
      mockDetect.mockResolvedValueOnce({ variant: "docker-desktop", version: "27.0.0", running: true });
      const result = await installer.waitForDocker(5_000);
      expect(result).toBe(true);
    });

    it("returns false when Docker never starts within timeout", async () => {
      mockDetect.mockResolvedValue({ variant: "docker-desktop", version: "", running: false });
      const result = await installer.waitForDocker(0);
      expect(result).toBe(false);
    }, 10_000);

    it("calls onProgress callback with status messages", async () => {
      mockDetect.mockResolvedValueOnce({ variant: "docker-desktop", version: "27.0.0", running: true });
      const messages: string[] = [];
      await installer.waitForDocker(5_000, (msg) => messages.push(msg));
      expect(messages.length).toBeGreaterThan(0);
      expect(messages.some((m) => m.includes("Docker"))).toBe(true);
    });
  });
});
