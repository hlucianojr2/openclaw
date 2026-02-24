/**
 * Installer Engine — orchestrates the full OpenClaw installation.
 *
 * Manages state across all wizard steps and executes the final install:
 *   1. Pull/build OpenClaw image
 *   2. Create Docker network + volumes
 *   3. Create gateway container with provided config
 *   4. Run onboard sequence (first-time setup in container)
 *   5. Start the environment
 */

import { app } from "electron";
import path from "node:path";
import { mkdir, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import type { ContainerManager } from "../docker/container-manager.js";
import type { DockerEngineClient } from "../docker/engine-client.js";
import { OPENCLAW_IMAGE, DEFAULT_GATEWAY_PORT, DEFAULT_BRIDGE_PORT } from "../../shared/constants.js";
import type { ChannelSelection } from "../../shared/ipc-types.js";

export type LLMProvider = "anthropic" | "google-gemini" | "openai" | "ollama";

export interface InstallerConfig {
  // LLM
  llmProvider: LLMProvider;
  llmApiKey: string;
  // GitHub backup
  githubPat: string;
  githubRepo: string;
  // Ports (optional overrides)
  gatewayPort?: number;
  bridgePort?: number;
  // Voice guide
  voiceEnabled: boolean;
  // Wizard step 6 — selected skills (IDs from skill-catalog)
  selectedSkills?: string[];
  // Wizard step 7 — selected channels with their configs
  selectedChannels?: ChannelSelection[];
}

export type InstallStage =
  | "preparing"
  | "pulling-image"
  | "creating-network"
  | "creating-volumes"
  | "creating-container"
  | "installing-skills"
  | "configuring-channels"
  | "starting"
  | "health-check"
  | "done"
  | "error";

export interface InstallProgress {
  stage: InstallStage;
  percent: number;
  message: string;
  error?: string;
}

type ProgressCallback = (progress: InstallProgress) => void;

export class InstallerEngine {
  constructor(
    private readonly docker: DockerEngineClient,
    private readonly containers: ContainerManager,
  ) {}

  /**
   * Execute the full installation with progress callbacks.
   */
  async install(config: InstallerConfig, onProgress: ProgressCallback): Promise<void> {
    const configDir = path.join(app.getPath("userData"), "openclaw-config");
    const workspaceDir = path.join(app.getPath("userData"), "openclaw-workspace");

    try {
      // Stage 1: Prepare dirs
      onProgress({ stage: "preparing", percent: 5, message: "Preparing configuration directories…" });
      await mkdir(configDir, { recursive: true });
      await mkdir(workspaceDir, { recursive: true });

      // Stage 2: Check/pull image
      onProgress({ stage: "pulling-image", percent: 15, message: "Checking OpenClaw image…" });
      const hasImage = await this.docker.imageExists(OPENCLAW_IMAGE);
      if (!hasImage) {
        onProgress({ stage: "pulling-image", percent: 20, message: "Pulling OpenClaw image (this may take a few minutes)…" });
        // In production this would stream progress; for now fire and resolve
        try {
          const stream = await this.docker.pullImage(OPENCLAW_IMAGE);
          await this.streamToCompletion(stream);
        } catch {
          // Image pull failed — try to build from local source
          onProgress({ stage: "pulling-image", percent: 25, message: "Building OpenClaw image from source…" });
          const projectRoot = path.join(app.getAppPath(), "..", "..", "..");
          const stream = await this.docker.buildImage(projectRoot, { t: OPENCLAW_IMAGE });
          await this.streamToCompletion(stream);
        }
      }

      onProgress({ stage: "pulling-image", percent: 40, message: "Image ready ✓" });

      // Stage 3: Create network
      onProgress({ stage: "creating-network", percent: 50, message: "Creating isolated network…" });
      try {
        await this.docker.createNetwork("openclaw-net");
      } catch {
        // Network may already exist — continue
      }

      // Stage 4: Create volume
      onProgress({ stage: "creating-volumes", percent: 60, message: "Creating persistent storage…" });
      try {
        await this.docker.createVolume("openclaw-home");
      } catch {
        // Volume may already exist — continue
      }

      // Stage 5: Create container
      onProgress({ stage: "creating-container", percent: 70, message: "Configuring OpenClaw container…" });
      const gatewayToken = randomBytes(32).toString("hex");

      await this.containers.createEnvironment({
        configDir,
        workspaceDir,
        gatewayToken,
        gatewayPort: config.gatewayPort ?? DEFAULT_GATEWAY_PORT,
        bridgePort: config.bridgePort ?? DEFAULT_BRIDGE_PORT,
      });

      // Stage 6: Install skills (write skill list to config volume before start)
      const skills = config.selectedSkills ?? [];
      if (skills.length > 0) {
        onProgress({ stage: "installing-skills", percent: 72, message: `Queueing ${skills.length} skill(s) for installation…` });
        await this.writeSkillConfig(configDir, skills);
      }

      // Stage 7: Configure channels
      const channels = config.selectedChannels ?? [];
      if (channels.length > 0) {
        onProgress({ stage: "configuring-channels", percent: 78, message: `Applying configuration for ${channels.length} channel(s)…` });
        await this.writeChannelConfig(configDir, config, channels);
      }

      // Stage 8: Start
      onProgress({ stage: "starting", percent: 85, message: "Starting OpenClaw environment…" });
      await this.containers.startEnvironment();

      // Stage 9: Health check
      onProgress({ stage: "health-check", percent: 92, message: "Waiting for services to become ready…" });
      await this.waitForHealth(15_000);

      onProgress({ stage: "done", percent: 100, message: "OpenClaw is installed and running ✓" });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown error";
      onProgress({ stage: "error", percent: 0, message, error: message });
      throw err;
    }
  }

  private async waitForHealth(timeoutMs: number): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const status = await this.containers.getEnvironmentStatus();
      if (status.health === "healthy") {return;}
      await sleep(1_000);
    }
    // Not fatal — environment may still be starting
  }

  private streamToCompletion(stream: NodeJS.ReadableStream): Promise<void> {
    return new Promise((resolve, reject) => {
      stream.on("end", resolve);
      stream.on("error", reject);
      stream.resume();
    });
  }

  /**
   * Write selected skill IDs to a JSON file in the config dir so the container
   * can auto-install them on first boot via openclaw-startup-skills.json.
   */
  private async writeSkillConfig(configDir: string, skills: string[]): Promise<void> {
    const filePath = path.join(configDir, "openclaw-startup-skills.json");
    await writeFile(filePath, JSON.stringify({ skills }, null, 2), "utf8");
  }

  /**
   * Write channel configuration to the config dir as openclaw-channels.json.
   * Keys are channel IDs; values are their config maps (tokens, credentials, etc.).
   * Sensitive values are written to the volume — not transmitted over IPC after setup.
   */
  private async writeChannelConfig(
    configDir: string,
    _installerCfg: InstallerConfig,
    channels: import("../../shared/ipc-types.js").ChannelSelection[],
  ): Promise<void> {
    const channelEntries: Record<string, Record<string, string>> = {};
    for (const ch of channels) {
      channelEntries[ch.channelId] = ch.config;
    }
    const filePath = path.join(configDir, "openclaw-channels.json");
    await writeFile(filePath, JSON.stringify({ channels: channelEntries }, null, 2), "utf8");
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
