/**
 * Tests for InstallerEngine — Phase 3 extensions (selectedSkills, selectedChannels).
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { InstallerConfig, InstallProgress } from "../../src/main/installer/installer-engine.js";

// ─── Mock Electron app ─────────────────────────────────────────────────────
vi.mock("electron", () => ({
  app: { getPath: (_: string) => "/tmp/occc-test", getAppPath: () => "/tmp/occc-app" },
}));

// ─── Mock fs/promises ──────────────────────────────────────────────────────
vi.mock("node:fs/promises", () => ({
  mkdir: vi.fn().mockResolvedValue(undefined),
  writeFile: vi.fn().mockResolvedValue(undefined),
}));

// ─── Minimal docker / container mocks ─────────────────────────────────────

const mockDocker = {
  imageExists: vi.fn().mockResolvedValue(true),
  pullImage: vi.fn(),
  buildImage: vi.fn(),
  createNetwork: vi.fn().mockResolvedValue(undefined),
  createVolume: vi.fn().mockResolvedValue(undefined),
};

const mockContainers = {
  createEnvironment: vi.fn().mockResolvedValue(undefined),
  startEnvironment: vi.fn().mockResolvedValue(undefined),
  getEnvironmentStatus: vi.fn().mockResolvedValue({ health: "healthy" }),
};

describe("InstallerEngine — selectedSkills & selectedChannels", () => {
  let engine: import("../../src/main/installer/installer-engine.js").InstallerEngine;
  let writeFile: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    vi.clearAllMocks();
    const { writeFile: wf } = await import("node:fs/promises");
    writeFile = wf as ReturnType<typeof vi.fn>;

    const { InstallerEngine } = await import("../../src/main/installer/installer-engine.js");
    engine = new InstallerEngine(
      mockDocker as never,
      mockContainers as never,
    );
  });

  it("completes without skills or channels", async () => {
    const progress: InstallProgress[] = [];
    await engine.install(baseConfig(), (p) => progress.push(p));

    const stages = progress.map((p) => p.stage);
    expect(stages).toContain("done");
    expect(stages).not.toContain("installing-skills");
    expect(stages).not.toContain("configuring-channels");
  });

  it("emits 'installing-skills' stage when skills are selected", async () => {
    const config = baseConfig({ selectedSkills: ["healthcheck", "weather"] });
    const progress: InstallProgress[] = [];
    await engine.install(config, (p) => progress.push(p));

    const stages = progress.map((p) => p.stage);
    expect(stages).toContain("installing-skills");
  });

  it("writes openclaw-startup-skills.json when skills selected", async () => {
    const config = baseConfig({ selectedSkills: ["healthcheck", "summarize"] });
    await engine.install(config, () => undefined);

    const calls = (writeFile).mock.calls;
    const skillCall = calls.find((c: unknown[]) => String(c[0]).endsWith("openclaw-startup-skills.json"));
    expect(skillCall).toBeDefined();
    const written = JSON.parse(String(skillCall![1])) as { skills: string[] };
    expect(written.skills).toEqual(["healthcheck", "summarize"]);
  });

  it("emits 'configuring-channels' stage when channels are selected", async () => {
    const config = baseConfig({
      selectedChannels: [{ channelId: "telegram", config: { botToken: "test-token" } }],
    });
    const progress: InstallProgress[] = [];
    await engine.install(config, (p) => progress.push(p));

    const stages = progress.map((p) => p.stage);
    expect(stages).toContain("configuring-channels");
  });

  it("writes openclaw-channels.json when channels selected", async () => {
    const config = baseConfig({
      selectedChannels: [
        { channelId: "telegram", config: { botToken: "123:abc" } },
        { channelId: "discord", config: { botToken: "MTk4…" } },
      ],
    });
    await engine.install(config, () => undefined);

    const calls = (writeFile).mock.calls;
    const chCall = calls.find((c: unknown[]) => String(c[0]).endsWith("openclaw-channels.json"));
    expect(chCall).toBeDefined();
    const written = JSON.parse(String(chCall![1])) as { channels: Record<string, unknown> };
    expect(written.channels["telegram"]).toEqual({ botToken: "123:abc" });
    expect(written.channels["discord"]).toEqual({ botToken: "MTk4…" });
  });

  it("stage order is correct when both skills and channels present", async () => {
    const config = baseConfig({
      selectedSkills: ["weather"],
      selectedChannels: [{ channelId: "telegram", config: { botToken: "x" } }],
    });
    const stages: string[] = [];
    await engine.install(config, (p) => stages.push(p.stage));

    const skillIdx = stages.indexOf("installing-skills");
    const channelIdx = stages.indexOf("configuring-channels");
    const startIdx = stages.indexOf("starting");
    expect(skillIdx).toBeLessThan(channelIdx);
    expect(channelIdx).toBeLessThan(startIdx);
  });
});

// ─── Helpers ───────────────────────────────────────────────────────────────

function baseConfig(overrides: Partial<InstallerConfig> = {}): InstallerConfig {
  return {
    llmProvider: "anthropic",
    llmApiKey: "sk-test",
    githubPat: "ghp_test",
    githubRepo: "user/openclaw-backup-abc12345",
    voiceEnabled: false,
    ...overrides,
  };
}
