/**
 * Installer IPC Handlers — registers all installer-related IPC channels.
 */

import { ipcMain } from "electron";
import { IPC_CHANNELS } from "../../shared/ipc-types.js";
import { SystemValidator } from "./system-validator.js";
import { DockerInstaller } from "./docker-installer.js";
import { VoiceGuide } from "./voice-guide.js";
import { GitHubBackupSetup } from "./github-setup.js";
import { InstallerEngine, type InstallerConfig } from "./installer-engine.js";
import { SKILL_CATALOG, findSkillById } from "./skill-catalog.js";
import { CHANNEL_CATALOG, validateChannelConfig } from "./channel-catalog.js";
import type { DockerEngineClient } from "../docker/engine-client.js";
import type { ContainerManager } from "../docker/container-manager.js";
import type { AuthEngine } from "../auth/auth-engine.js";

/**
 * Coerce every value in a raw channel config object to a string so
 * validateChannelConfig can safely call value.trim() without risk of
 * TypeError. The renderer may send numbers, booleans, or nulls for
 * fields that are typed as strings in the catalog.
 */
function coerceChannelConfig(raw: object): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (v === null || v === undefined) {
      out[k] = "";
    } else if (typeof v === "string") {
      out[k] = v;
    } else if (typeof v === "number" || typeof v === "boolean") {
      out[k] = String(v);
    } else {
      out[k] = JSON.stringify(v);
    }
  }
  return out;
}

export function registerInstallerIpcHandlers(
  docker: DockerEngineClient,
  containers: ContainerManager,
  auth: AuthEngine,
): void {
  const validator = new SystemValidator();
  const dockerInstaller = new DockerInstaller();
  const voice = new VoiceGuide();
  const githubSetup = new GitHubBackupSetup();
  const engine = new InstallerEngine(docker, containers);

  // ─── System Validation ──────────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.INSTALL_VALIDATE_SYSTEM, async () => {
    return validator.validate();
  });

  // ─── Docker ─────────────────────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.INSTALL_DOCKER_OPTIONS, () => {
    return dockerInstaller.getOptions();
  });

  ipcMain.handle(IPC_CHANNELS.INSTALL_OPEN_DOCKER_DOWNLOAD, async () => {
    await dockerInstaller.openDockerDesktopDownload();
  });

  ipcMain.handle(IPC_CHANNELS.INSTALL_DOCKER_CE_COMMAND, () => {
    return dockerInstaller.getDockerCEInstallCommand();
  });

  ipcMain.handle(IPC_CHANNELS.INSTALL_START_DOCKER_DESKTOP, async () => {
    return dockerInstaller.startDockerDesktop();
  });

  ipcMain.handle(IPC_CHANNELS.INSTALL_VERIFY_DOCKER, async () => {
    return dockerInstaller.verify();
  });

  // ─── Voice Guide ────────────────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.INSTALL_VOICE_SPEAK, async (_event, text: unknown) => {
    // Validate: must be a string, max 512 chars, no ASCII control characters
    if (typeof text !== "string") { return; }
    // Clamp the raw input first (before stripping) so an adversarial renderer
    // cannot force unbounded work via control-char-heavy payloads, then
    // strip ASCII control characters (0x00–0x1F, DEL) and bound the clean result.
    // eslint-disable-next-line no-control-regex
    const safe = text.slice(0, 1024).replace(/[\x00-\x1f\x7f]/g, "").slice(0, 512);
    if (!safe) { return; }
    await voice.speak(safe);
  });

  ipcMain.handle(IPC_CHANNELS.INSTALL_VOICE_SET_ENABLED, (_event, enabled: unknown) => {
    voice.setEnabled(enabled === true);
    return enabled === true;
  });

  ipcMain.handle(IPC_CHANNELS.INSTALL_VOICE_STOP, () => {
    voice.stop();
  });

  // ─── GitHub Backup ──────────────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.INSTALL_GITHUB_VALIDATE_PAT, async (_event, pat: unknown) => {
    if (typeof pat !== "string") { return { ok: false, reason: "Invalid PAT type" }; }
    return githubSetup.validatePAT(pat);
  });

  ipcMain.handle(IPC_CHANNELS.INSTALL_GITHUB_CHECK_SCOPE, async (_event, pat: unknown) => {
    if (typeof pat !== "string") { return false; }
    return githubSetup.checkRepoScope(pat);
  });

  ipcMain.handle(IPC_CHANNELS.INSTALL_GITHUB_CREATE_REPO, async (_event, pat: unknown) => {
    if (typeof pat !== "string") { throw new Error("Invalid PAT"); }
    return githubSetup.createBackupRepo(pat);
  });

  // ─── Install ────────────────────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.INSTALL_RUN, async (event, config: InstallerConfig) => {
    // Guard: installer can only run during first-run setup.
    // After the initial user is created this channel must never execute again.
    if (!auth.isFirstRun()) {
      throw new Error("Installation already completed — INSTALL_RUN is disabled");
    }

    // Guard: validate required string fields (IPC args are plain JSON; TS types
    // are not enforced at runtime — a malformed renderer can send any value).
    if (typeof config.llmProvider !== "string" || !config.llmProvider) {
      throw new Error("llmProvider must be a non-empty string");
    }
    if (typeof config.llmApiKey !== "string" || !config.llmApiKey) {
      throw new Error("llmApiKey must be a non-empty string");
    }

    // Guard: validate optional port overrides before they reach the Docker layer.
    const portInRange = (p: unknown): boolean =>
      typeof p === "number" && Number.isInteger(p) && p >= 1024 && p <= 65535;
    if (config.gatewayPort !== undefined && !portInRange(config.gatewayPort)) {
      throw new Error("gatewayPort must be an integer in range 1024–65535");
    }
    if (config.bridgePort !== undefined && !portInRange(config.bridgePort)) {
      throw new Error("bridgePort must be an integer in range 1024–65535");
    }

    // Guard: reject any skill not in the catalog or requiring elevated auth.
    // Admin-review skills cannot be installed during the pre-auth wizard.
    const selectedSkills: string[] = Array.isArray(config.selectedSkills) ? config.selectedSkills : [];
    const disallowedSkills = selectedSkills.filter((id) => {
      const entry = findSkillById(id);
      return !entry || entry.approvalLevel === "admin-review" || entry.approvalLevel === "blocked";
    });
    if (disallowedSkills.length > 0) {
      throw new Error(`Disallowed or unknown skills: ${disallowedSkills.join(", ")}`);
    }

    // Guard: re-validate all channel configs server-side before the engine writes
    // them to disk (the renderer may have altered values after the validate step).
    const selectedChannels = Array.isArray(config.selectedChannels) ? config.selectedChannels : [];
    for (const ch of selectedChannels) {
      if (typeof ch.channelId !== "string" || typeof ch.config !== "object" || ch.config === null) {
        throw new Error(`Invalid channel entry: ${JSON.stringify(ch)}`);
      }
      const result = validateChannelConfig(ch.channelId, coerceChannelConfig(ch.config));
      if (!result.valid) {
        throw new Error(`Channel config invalid for '${ch.channelId}': ${result.error}`);
      }
    }

    await engine.install(config, (progress) => {
      // Push progress to the renderer via the sender
      event.sender.send(IPC_CHANNELS.INSTALL_PROGRESS, progress);
    });
  });

  // ─── Skill Catalog (Wizard Step 6) ─────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.INSTALL_GET_SKILL_CATALOG, () => {
    return SKILL_CATALOG;
  });

  // ─── Channel Catalog (Wizard Step 7) ───────────────────────────────

  ipcMain.handle(IPC_CHANNELS.INSTALL_GET_CHANNEL_CATALOG, () => {
    return CHANNEL_CATALOG;
  });

  ipcMain.handle(
    IPC_CHANNELS.INSTALL_CHANNEL_VALIDATE,
    (_event, channelId: unknown, config: unknown) => {
      if (typeof channelId !== "string") {
        return { valid: false, error: "channelId must be a string" };
      }
      if (typeof config !== "object" || config === null || Array.isArray(config)) {
        return { valid: false, error: "config must be an object" };
      }
      return validateChannelConfig(channelId, coerceChannelConfig(config));
    },
  );
}
