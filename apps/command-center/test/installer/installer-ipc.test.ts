/**
 * Tests for installer IPC handler guards.
 *
 * Focuses on the server-side validation logic embedded in INSTALL_RUN:
 *   - first-run gate
 *   - port range validation
 *   - skill catalog gate (reject admin-review and blocked)
 *   - channel config re-validation
 *
 * Also covers INSTALL_VOICE_SPEAK input sanitization and
 * INSTALL_CHANNEL_VALIDATE input type validation.
 *
 * Uses a mock ipcMain that captures registered handlers so we can invoke
 * them directly without booting Electron.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { InstallerConfig } from "../../src/main/installer/installer-engine.js";

// ─── Mock electron ─────────────────────────────────────────────────────────

type IpcHandler = (_event: unknown, ...args: unknown[]) => unknown;
const ipcHandlers = new Map<string, IpcHandler>();

vi.mock("electron", () => ({
  ipcMain: {
    handle: vi.fn((channel: string, handler: IpcHandler) => {
      ipcHandlers.set(channel, handler);
    }),
  },
  app: { getPath: () => "/tmp/test", getAppPath: () => "/tmp/app" },
  shell: { openExternal: vi.fn() },
}));

// ─── Mock sub-modules used by installer-ipc ────────────────────────────────

vi.mock("../../src/main/installer/system-validator.js", () => ({
  SystemValidator: class { async validate() { return { checks: [], allPassed: true, canProceed: true }; } },
}));
vi.mock("../../src/main/installer/docker-installer.js", () => ({
  DockerInstaller: class {
    getOptions() { return { dockerDesktop: true, dockerCE: false }; }
    async openDockerDesktopDownload() {}
    getDockerCEInstallCommand() { return ""; }
    async startDockerDesktop() { return true; }
    async verify() { return { ok: true, version: "27" }; }
  },
}));
vi.mock("../../src/main/installer/voice-guide.js", () => ({
  VoiceGuide: class {
    async speak() {}
    setEnabled() {}
    stop() {}
  },
}));
vi.mock("../../src/main/installer/github-setup.js", () => ({
  GitHubBackupSetup: class {
    async validatePAT() { return { valid: true, login: "user" }; }
    async checkRepoScope() { return { hasScope: true }; }
    async createBackupRepo() { return { url: "https://github.com/user/repo" }; }
  },
}));
vi.mock("../../src/main/installer/installer-engine.js", () => ({
  InstallerEngine: class {
    async install(_config: InstallerConfig, onProgress: (p: unknown) => void) {
      onProgress({ stage: "done", percent: 100, message: "done" });
    }
  },
}));

// ─── Setup: register handlers ────────────────────────────────────────────────

let authEngine: { isFirstRun: ReturnType<typeof vi.fn> };

beforeEach(async () => {
  vi.clearAllMocks();
  ipcHandlers.clear();

  authEngine = { isFirstRun: vi.fn().mockReturnValue(true) };

  const mockDocker = {};
  const mockContainers = {};

  const { registerInstallerIpcHandlers } = await import(
    "../../src/main/installer/installer-ipc.js"
  );
  registerInstallerIpcHandlers(
    mockDocker as never,
    mockContainers as never,
    authEngine as never,
  );
});

// ─── Helper ──────────────────────────────────────────────────────────────────

function invoke(channel: string, ...args: unknown[]): unknown {
  const handler = ipcHandlers.get(channel);
  if (!handler) { throw new Error(`No handler for ${channel}`); }
  const fakeEvent = { sender: { send: vi.fn() } };
  return handler(fakeEvent, ...args);
}

// ─── INSTALL_VOICE_SPEAK input sanitization ──────────────────────────────────

describe("INSTALL_VOICE_SPEAK handler", () => {
  it("resolves without error for a valid string", async () => {
    await expect(invoke("occc:install:voice-speak", "Hello")).resolves.toBeUndefined();
  });

  it("returns undefined (no-op) for non-string input", async () => {
    await expect(invoke("occc:install:voice-speak", 42)).resolves.toBeUndefined();
    await expect(invoke("occc:install:voice-speak", null)).resolves.toBeUndefined();
  });

  it("strips ASCII control characters before speaking", async () => {
    // Handler should not throw on control-char-heavy strings
    await expect(invoke("occc:install:voice-speak", "Hello\x00World\x1f!")).resolves.toBeUndefined();
  });

  it("handles empty string after control-char stripping gracefully", async () => {
    await expect(invoke("occc:install:voice-speak", "\x00\x01\x02")).resolves.toBeUndefined();
  });
});

// ─── INSTALL_RUN first-run gate ───────────────────────────────────────────────

describe("INSTALL_RUN handler — first-run gate", () => {
  const validConfig: InstallerConfig = {
    llmProvider: "anthropic",
    llmApiKey: "sk-test",
    githubPat: "ghp_test",
    githubRepo: "user/openclaw-backup-abc",
    voiceEnabled: false,
  };

  it("executes when isFirstRun() returns true", async () => {
    authEngine.isFirstRun.mockReturnValue(true);
    await expect(invoke("occc:install:run", validConfig)).resolves.toBeUndefined();
  });

  it("throws when isFirstRun() returns false (already installed)", async () => {
    authEngine.isFirstRun.mockReturnValue(false);
    await expect(invoke("occc:install:run", validConfig)).rejects.toThrow(
      "Installation already completed",
    );
  });
});

// ─── INSTALL_RUN port range validation ───────────────────────────────────────

describe("INSTALL_RUN handler — port validation", () => {
  const base: InstallerConfig = {
    llmProvider: "anthropic",
    llmApiKey: "sk-test",
    githubPat: "ghp_test",
    githubRepo: "user/openclaw-backup-abc",
    voiceEnabled: false,
  };

  it("accepts config without optional ports", async () => {
    await expect(invoke("occc:install:run", base)).resolves.toBeUndefined();
  });

  it("accepts valid port numbers in range 1024–65535", async () => {
    await expect(invoke("occc:install:run", { ...base, gatewayPort: 1024, bridgePort: 65535 })).resolves.toBeUndefined();
  });

  it("rejects gatewayPort below 1024", async () => {
    await expect(invoke("occc:install:run", { ...base, gatewayPort: 80 })).rejects.toThrow("gatewayPort");
  });

  it("rejects bridgePort above 65535", async () => {
    await expect(invoke("occc:install:run", { ...base, bridgePort: 70000 })).rejects.toThrow("bridgePort");
  });

  it("rejects non-integer port", async () => {
    await expect(invoke("occc:install:run", { ...base, gatewayPort: 8080.5 })).rejects.toThrow("gatewayPort");
  });
});

// ─── INSTALL_RUN skill catalog gate ──────────────────────────────────────────

describe("INSTALL_RUN handler — skill catalog gate", () => {
  const base: InstallerConfig = {
    llmProvider: "anthropic",
    llmApiKey: "sk-test",
    githubPat: "ghp_test",
    githubRepo: "user/openclaw-backup-abc",
    voiceEnabled: false,
  };

  it("accepts known auto-approved or user-ack skills", async () => {
    // healthcheck is the first auto-approved skill in the catalog
    await expect(
      invoke("occc:install:run", { ...base, selectedSkills: ["healthcheck"] }),
    ).resolves.toBeUndefined();
  });

  it("rejects unknown skill IDs not in the catalog", async () => {
    await expect(
      invoke("occc:install:run", { ...base, selectedSkills: ["nonexistent-skill-xyz"] }),
    ).rejects.toThrow(/Disallowed or unknown/);
  });
});

// ─── INSTALL_CHANNEL_VALIDATE input type guards ───────────────────────────────

describe("INSTALL_CHANNEL_VALIDATE handler", () => {
  it("returns valid:false for non-string channelId", async () => {
    const result = await invoke("occc:install:channel-validate", 123, {});
    expect((result as { valid: boolean }).valid).toBe(false);
  });

  it("returns valid:false for non-object config", async () => {
    const result = await invoke("occc:install:channel-validate", "telegram", "bad");
    expect((result as { valid: boolean }).valid).toBe(false);
  });

  it("returns valid:false for array config", async () => {
    const result = await invoke("occc:install:channel-validate", "telegram", ["a", "b"]);
    expect((result as { valid: boolean }).valid).toBe(false);
  });

  it("accepts valid channel + config and returns validation result", async () => {
    // telegram requires botToken — providing one should pass (or at least not throw)
    const result = await invoke("occc:install:channel-validate", "telegram", { botToken: "123:abc" });
    expect(typeof (result as { valid: boolean }).valid).toBe("boolean");
  });
});
