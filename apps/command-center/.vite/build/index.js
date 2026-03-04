"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
const electron = require("electron");
const path = require("node:path");
const os = require("node:os");
const node_child_process = require("node:child_process");
const node_util = require("node:util");
const node_fs = require("node:fs");
const Dockerode = require("dockerode");
const node_crypto = require("node:crypto");
const require$$0 = require("crypto");
const node_net = require("node:net");
const promises = require("node:fs/promises");
var _documentCurrentScript = typeof document !== "undefined" ? document.currentScript : null;
const APP_NAME = "OpenClaw Command Center";
const DEFAULT_GATEWAY_PORT = 18789;
const DEFAULT_BRIDGE_PORT = 18790;
const AUTH_SESSION_TIMEOUT_MS = 30 * 60 * 1e3;
const OPENCLAW_IMAGE = "openclaw:local";
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  // React needs inline for dynamic styles
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self' ws://localhost:* http://localhost:*",
  "frame-src 'none'",
  "object-src 'none'",
  "base-uri 'self'"
].join("; ");
class WindowManager {
  mainWindow = null;
  async createMainWindow() {
    const { width: screenWidth, height: screenHeight } = electron.screen.getPrimaryDisplay().workAreaSize;
    this.mainWindow = new electron.BrowserWindow({
      width: Math.min(1400, screenWidth),
      height: Math.min(900, screenHeight),
      minWidth: 900,
      minHeight: 600,
      title: APP_NAME,
      titleBarStyle: process.platform === "darwin" ? "hiddenInset" : "default",
      show: false,
      // Show after ready-to-show for smooth launch
      backgroundColor: "#0a0a0f",
      webPreferences: {
        preload: path.join(__dirname, "../preload/index.js"),
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true,
        webviewTag: false,
        spellcheck: false,
        devTools: process.env.NODE_ENV !== "production"
      }
    });
    this.mainWindow.webContents.session.webRequest.onHeadersReceived((details, callback) => {
      callback({
        responseHeaders: {
          ...details.responseHeaders,
          "Content-Security-Policy": [CSP]
        }
      });
    });
    this.mainWindow.once("ready-to-show", () => {
      this.mainWindow?.show();
    });
    this.mainWindow.on("close", (event) => {
      if (process.platform === "darwin") {
        event.preventDefault();
        this.mainWindow?.hide();
      }
    });
    this.mainWindow.on("closed", () => {
      this.mainWindow = null;
    });
    {
      await this.mainWindow.loadURL("http://localhost:5175");
    }
    return this.mainWindow;
  }
  focusMainWindow() {
    if (this.mainWindow) {
      if (this.mainWindow.isMinimized()) {
        this.mainWindow.restore();
      }
      this.mainWindow.show();
      this.mainWindow.focus();
    } else {
      void this.createMainWindow();
    }
  }
  getMainWindow() {
    return this.mainWindow;
  }
}
const ICON_SIZE = 16;
function createStatusIcon(health) {
  const colors = {
    healthy: "#22c55e",
    degraded: "#eab308",
    unhealthy: "#ef4444",
    stopped: "#6b7280",
    unknown: "#6b7280"
  };
  const color = colors[health];
  const svg = `
    <svg xmlns="http://www.w3.org/2000/svg" width="${ICON_SIZE}" height="${ICON_SIZE}">
      <circle cx="${ICON_SIZE / 2}" cy="${ICON_SIZE / 2}" r="${ICON_SIZE / 2 - 1}"
              fill="${color}" stroke="rgba(255,255,255,0.3)" stroke-width="1"/>
    </svg>
  `;
  const dataUrl = `data:image/svg+xml;base64,${Buffer.from(svg).toString("base64")}`;
  return electron.nativeImage.createFromDataURL(dataUrl);
}
class TrayManager {
  constructor(windowManager2) {
    this.windowManager = windowManager2;
  }
  tray = null;
  currentHealth = "unknown";
  create() {
    const icon = createStatusIcon(this.currentHealth);
    this.tray = new electron.Tray(icon);
    this.tray.setToolTip(`${APP_NAME} — ${this.currentHealth}`);
    this.updateContextMenu();
    this.tray.on("click", () => {
      this.windowManager.focusMainWindow();
    });
  }
  updateHealth(health) {
    this.currentHealth = health;
    if (!this.tray) {
      return;
    }
    this.tray.setImage(createStatusIcon(health));
    this.tray.setToolTip(`${APP_NAME} — ${health}`);
    this.updateContextMenu();
  }
  updateContextMenu() {
    if (!this.tray) {
      return;
    }
    const statusLabel = this.currentHealth === "healthy" ? "● Environment Running" : this.currentHealth === "stopped" ? "○ Environment Stopped" : `⚠ Environment ${this.currentHealth}`;
    const menu = electron.Menu.buildFromTemplate([
      { label: statusLabel, enabled: false },
      { type: "separator" },
      {
        label: "Open Command Center",
        click: () => this.windowManager.focusMainWindow()
      },
      { type: "separator" },
      {
        label: "Start Environment",
        enabled: this.currentHealth === "stopped",
        click: () => {
        }
      },
      {
        label: "Stop Environment",
        enabled: this.currentHealth !== "stopped",
        click: () => {
        }
      },
      { type: "separator" },
      {
        label: "Quit",
        click: () => {
          electron.app.quit();
        }
      }
    ]);
    this.tray.setContextMenu(menu);
  }
  destroy() {
    this.tray?.destroy();
    this.tray = null;
  }
}
const IPC_CHANNELS = {
  // Auth
  AUTH_LOGIN: "occc:auth:login",
  AUTH_BIOMETRIC: "occc:auth:biometric",
  AUTH_VERIFY_TOTP: "occc:auth:verify-totp",
  AUTH_LOGOUT: "occc:auth:logout",
  AUTH_SESSION: "occc:auth:session",
  AUTH_ELEVATE: "occc:auth:elevate",
  // Auth — First Run
  AUTH_IS_FIRST_RUN: "occc:auth:is-first-run",
  AUTH_CREATE_INITIAL_USER: "occc:auth:create-initial-user",
  AUTH_CONFIRM_TOTP: "occc:auth:confirm-totp",
  AUTH_BIOMETRIC_AVAILABLE: "occc:auth:biometric-available",
  AUTH_ENROLL_BIOMETRIC: "occc:auth:enroll-biometric",
  // Auth — User Management
  AUTH_LIST_USERS: "occc:auth:list-users",
  AUTH_CREATE_USER: "occc:auth:create-user",
  AUTH_UPDATE_ROLE: "occc:auth:update-role",
  AUTH_RESET_PASSWORD: "occc:auth:reset-password",
  AUTH_DELETE_USER: "occc:auth:delete-user",
  AUTH_AUDIT_LOG: "occc:auth:audit-log",
  // Auth — Self-service
  AUTH_CHANGE_PASSWORD: "occc:auth:change-password",
  // Environment
  ENV_STATUS: "occc:env:status",
  ENV_CREATE: "occc:env:create",
  ENV_START: "occc:env:start",
  ENV_STOP: "occc:env:stop",
  ENV_DESTROY: "occc:env:destroy",
  ENV_LOGS: "occc:env:logs",
  // Docker
  DOCKER_INFO: "occc:docker:info",
  // Config
  CONFIG_GET: "occc:config:get",
  CONFIG_SECTIONS: "occc:config:sections",
  // Skills
  SKILLS_LIST: "occc:skills:list",
  // System
  SYSTEM_VALIDATE: "occc:system:validate",
  SYSTEM_PLATFORM: "occc:system:platform"
};
const execFileAsync = node_util.promisify(node_child_process.execFile);
const DOCKER_DESKTOP_INDICATORS = {
  darwin: [
    "/Applications/Docker.app",
    ...process.env.HOME ? [`${process.env.HOME}/Applications/Docker.app`] : []
  ],
  win32: [
    "C:\\Program Files\\Docker\\Docker\\Docker Desktop.exe",
    ...process.env.LOCALAPPDATA ? [`${process.env.LOCALAPPDATA}\\Docker\\Docker Desktop.exe`] : []
  ],
  linux: [
    "/opt/docker-desktop/bin/docker-desktop"
  ]
};
class EngineDetector {
  /**
   * Detect the installed container engine and its status.
   */
  async detect() {
    const dockerResult = await this.probeDocker();
    if (dockerResult) {
      return dockerResult;
    }
    const podmanResult = await this.probePodman();
    if (podmanResult) {
      return podmanResult;
    }
    return {
      variant: "none",
      version: "",
      apiVersion: "",
      running: false
    };
  }
  /**
   * Check if Docker Desktop or Docker CE can be installed on this platform.
   */
  getInstallOptions() {
    const platform = process.platform;
    return {
      dockerDesktop: platform === "darwin" || platform === "win32" || platform === "linux",
      dockerCE: platform === "linux"
    };
  }
  async probeDocker() {
    try {
      const { stdout } = await execFileAsync("docker", ["version", "--format", "json"], {
        timeout: 1e4
      });
      const info = JSON.parse(stdout);
      const clientVersion = info.Client?.Version ?? "";
      const apiVersion = info.Client?.ApiVersion ?? "";
      const serverRunning = !!info.Server?.Version;
      const variant = this.isDockerDesktop() ? "docker-desktop" : "docker-ce";
      return {
        variant,
        version: clientVersion,
        apiVersion,
        running: serverRunning
      };
    } catch {
      return null;
    }
  }
  async probePodman() {
    try {
      const { stdout } = await execFileAsync("podman", ["version", "--format", "json"], {
        timeout: 1e4
      });
      const info = JSON.parse(stdout);
      return {
        variant: "podman",
        version: info.Client?.Version ?? info.Version ?? "",
        apiVersion: info.Client?.APIVersion ?? "",
        running: true
        // If podman version succeeds, it's usable
      };
    } catch {
      return null;
    }
  }
  /**
   * Heuristic: check if Docker Desktop is installed by looking for
   * platform-specific indicators (app bundles, executables).
   */
  isDockerDesktop() {
    const indicators = DOCKER_DESKTOP_INDICATORS[process.platform] ?? [];
    return indicators.some((p) => node_fs.existsSync(p));
  }
}
class ImageManager {
  constructor(client) {
    this.client = client;
  }
  /**
   * Pull an image and stream progress events to the callback.
   * Resolves when the pull is fully complete.
   */
  async pull(imageName, onProgress) {
    const stream = await this.client.pullImage(imageName);
    await this.followProgress(stream, onProgress);
  }
  /**
   * Ensure an image is present locally; pull it if not.
   * Returns true if a pull was performed, false if already present.
   */
  async ensure(imageName, onProgress) {
    const exists = await this.client.imageExists(imageName);
    if (exists) {
      return false;
    }
    await this.pull(imageName, onProgress);
    return true;
  }
  /**
   * List all locally available OpenClaw images (tagged openclaw/*).
   */
  async list() {
    const images = await this.client.listImages();
    return images.filter(
      (img) => (img.RepoTags ?? []).some(
        (tag) => tag.startsWith("openclaw/") || tag.startsWith("openclaw:")
      )
    ).map((img) => this.toSummary(img));
  }
  /**
   * Inspect a specific image by name/tag.
   */
  async inspect(imageName) {
    return this.client.inspectImage(imageName);
  }
  /**
   * Get the digest (sha256) of an image for integrity checking.
   */
  async getDigest(imageName) {
    try {
      const info = await this.inspect(imageName);
      return info.RepoDigests?.[0] ?? null;
    } catch {
      return null;
    }
  }
  /**
   * Remove an image by name. Force-removes even if tagged.
   */
  async remove(imageName, force = false) {
    await this.client.removeImage(imageName, force);
  }
  // ─── Helpers ────────────────────────────────────────────────────────────
  followProgress(stream, onProgress) {
    return new Promise((resolve, reject) => {
      this.client.followStreamProgress(
        stream,
        (err) => {
          if (err) {
            reject(err);
          } else {
            resolve();
          }
        },
        onProgress ? (event) => onProgress(event) : void 0
      );
    });
  }
  toSummary(img) {
    return {
      id: img.Id,
      repoTags: img.RepoTags ?? [],
      sizeBytes: img.Size,
      created: img.Created,
      digest: img.Id
      // short fallback; use getDigest() for repo digest
    };
  }
}
class NetworkManager {
  constructor(client) {
    this.client = client;
  }
  /**
   * Create an isolated bridge network for an OpenClaw environment.
   * Returns the new network ID.
   */
  async create(name) {
    const network = await this.client.createNetwork(name);
    const info = await network.inspect();
    return info.Id;
  }
  /**
   * Ensure a network exists, creating it if absent.
   * Returns the network ID.
   */
  async ensure(name) {
    const networks = await this.client.listManagedNetworks();
    const existing = networks.find((n) => n.Name === name);
    if (existing?.Id) {
      return existing.Id;
    }
    return this.create(name);
  }
  /**
   * Remove a network by ID.
   * Silently ignores "not found" errors (idempotent).
   */
  async remove(id) {
    try {
      await this.client.removeNetwork(id);
    } catch (err) {
      if (!isNotFound$1(err)) {
        throw err;
      }
    }
  }
  /**
   * Remove a network by name (looks up ID first).
   */
  async removeByName(name) {
    const networks = await this.client.listManagedNetworks();
    const found = networks.find((n) => n.Name === name);
    if (found?.Id) {
      await this.remove(found.Id);
    }
  }
  /**
   * List all OCCC-managed networks.
   */
  async list() {
    const networks = await this.client.listManagedNetworks();
    return networks.map((n) => ({
      id: n.Id ?? "",
      name: n.Name ?? "",
      driver: n.Driver ?? "bridge",
      created: n.Created ?? "",
      containers: Object.keys(n.Containers ?? {}).length
    }));
  }
  /**
   * Check whether a network with the given name already exists.
   */
  async exists(name) {
    const networks = await this.client.listManagedNetworks();
    return networks.some((n) => n.Name === name);
  }
}
function isNotFound$1(err) {
  if (err instanceof Error) {
    return err.message.includes("404") || err.message.toLowerCase().includes("no such network");
  }
  return false;
}
class VolumeManager {
  constructor(client) {
    this.client = client;
  }
  /**
   * Create a named persistent volume for OpenClaw data.
   * Returns the volume name.
   */
  async create(name) {
    await this.client.createVolume(name);
    return name;
  }
  /**
   * Ensure a volume exists, creating it if absent.
   * Returns the volume name.
   */
  async ensure(name) {
    const volumes = await this.client.listManagedVolumes();
    const existing = volumes.find((v) => v.Name === name);
    if (existing) {
      return existing.Name;
    }
    return this.create(name);
  }
  /**
   * Remove a named volume. Silently ignores "not found" errors (idempotent).
   * WARNING: destroys all data stored in the volume.
   */
  async remove(name) {
    try {
      await this.client.removeVolume(name);
    } catch (err) {
      if (!isNotFound(err)) {
        throw err;
      }
    }
  }
  /**
   * List all OCCC-managed volumes.
   */
  async list() {
    const volumes = await this.client.listManagedVolumes();
    return volumes.map((v) => ({
      name: v.Name,
      driver: v.Driver,
      mountpoint: v.Mountpoint,
      created: v.CreatedAt ?? "",
      labels: v.Labels ?? {}
    }));
  }
  /**
   * Check whether a volume with the given name already exists.
   */
  async exists(name) {
    const volumes = await this.client.listManagedVolumes();
    return volumes.some((v) => v.Name === name);
  }
  /**
   * Get detailed info on a single volume.
   */
  async inspect(name) {
    const volumes = await this.client.listManagedVolumes();
    const found = volumes.find((v) => v.Name === name);
    if (!found) {
      return null;
    }
    return {
      name: found.Name,
      driver: found.Driver,
      mountpoint: found.Mountpoint,
      created: found.CreatedAt ?? "",
      labels: found.Labels ?? {}
    };
  }
}
function isNotFound(err) {
  if (err instanceof Error) {
    return err.message.includes("404") || err.message.toLowerCase().includes("no such volume");
  }
  return false;
}
class ComposeOrchestrator {
  constructor(containers, images, networks, volumes) {
    this.containers = containers;
    this.images = images;
    this.networks = networks;
    this.volumes = volumes;
  }
  static NETWORK_NAME = "openclaw-net";
  static VOLUMES = ["openclaw-home"];
  /**
   * Bring the full stack up — idempotent, safe to call when already running.
   */
  async up(config, onProgress) {
    const image = config.image ?? OPENCLAW_IMAGE;
    const networkId = await this.networks.ensure(ComposeOrchestrator.NETWORK_NAME);
    const volumeNames = [];
    for (const vol of ComposeOrchestrator.VOLUMES) {
      const name = await this.volumes.ensure(vol);
      volumeNames.push(name);
    }
    const imagesPulled = await this.images.ensure(image, onProgress);
    try {
      await this.containers.createEnvironment({
        configDir: config.configDir,
        workspaceDir: config.workspaceDir,
        gatewayToken: config.gatewayToken,
        gatewayPort: config.gatewayPort ?? DEFAULT_GATEWAY_PORT,
        bridgePort: config.bridgePort ?? DEFAULT_BRIDGE_PORT,
        image,
        network: ComposeOrchestrator.NETWORK_NAME
      });
    } catch (err) {
      await this.networks.removeByName(ComposeOrchestrator.NETWORK_NAME).catch(() => {
      });
      throw err;
    }
    return { networkId, volumeNames, imagesPulled };
  }
  /**
   * Stop all running containers without destroying data.
   */
  async stop() {
    await this.containers.stopEnvironment();
  }
  /**
   * Start all stopped containers (without recreating anything).
   */
  async start() {
    await this.containers.startEnvironment();
  }
  /**
   * Tear down all containers and the network.
   * Volumes are intentionally preserved (data is safe).
   */
  async down() {
    await this.containers.destroyEnvironment();
  }
  /**
   * Full reset — tears down everything INCLUDING volumes (destroys data).
   * Requires explicit opt-in to prevent accidental data loss.
   */
  async purge() {
    await this.containers.destroyEnvironment();
    for (const vol of ComposeOrchestrator.VOLUMES) {
      await this.volumes.remove(vol);
    }
    await this.networks.removeByName(ComposeOrchestrator.NETWORK_NAME);
  }
}
function requireSession(token, sessions) {
  if (typeof token !== "string" || !sessions.resolve(token)) {
    throw new Error("Unauthorized");
  }
}
function requireElevatedSession(token, sessions) {
  if (typeof token !== "string") {
    throw new Error("Unauthorized");
  }
  const session = sessions.resolve(token);
  if (!session) {
    throw new Error("Unauthorized");
  }
  if (!session.elevated) {
    throw new Error("Elevated session required");
  }
}
function validateStackConfig(raw) {
  if (typeof raw !== "object" || raw === null) {
    throw new Error("Invalid environment config: expected object");
  }
  const obj = raw;
  const { configDir, workspaceDir, gatewayToken } = obj;
  if (typeof configDir !== "string" || !configDir) {
    throw new Error("configDir must be a non-empty string");
  }
  if (!path.isAbsolute(configDir) || configDir.includes("\0")) {
    throw new Error("configDir must be an absolute path without null bytes");
  }
  if (typeof workspaceDir !== "string" || !workspaceDir) {
    throw new Error("workspaceDir must be a non-empty string");
  }
  if (!path.isAbsolute(workspaceDir) || workspaceDir.includes("\0")) {
    throw new Error("workspaceDir must be an absolute path without null bytes");
  }
  if (typeof gatewayToken !== "string" || !gatewayToken) {
    throw new Error("gatewayToken must be a non-empty string");
  }
  if (gatewayToken.length > 512 || gatewayToken.includes("\0")) {
    throw new Error("gatewayToken is invalid");
  }
  return {
    configDir: path.resolve(configDir),
    // normalize without changing semantics
    workspaceDir: path.resolve(workspaceDir),
    gatewayToken,
    gatewayPort: typeof obj.gatewayPort === "number" ? obj.gatewayPort : void 0,
    bridgePort: typeof obj.bridgePort === "number" ? obj.bridgePort : void 0,
    image: typeof obj.image === "string" && obj.image ? obj.image : void 0
  };
}
function registerIpcHandlers(deps) {
  const { dockerClient: dockerClient2, containerManager: containerManager2, sessionManager: sessionManager2 } = deps;
  const detector = new EngineDetector();
  const imageManager = new ImageManager(dockerClient2);
  const networkManager = new NetworkManager(dockerClient2);
  const volumeManager = new VolumeManager(dockerClient2);
  const orchestrator = new ComposeOrchestrator(
    containerManager2,
    imageManager,
    networkManager,
    volumeManager
  );
  electron.ipcMain.handle(IPC_CHANNELS.DOCKER_INFO, async () => {
    return detector.detect();
  });
  electron.ipcMain.handle(IPC_CHANNELS.ENV_STATUS, async (_event, token) => {
    requireSession(token, sessionManager2);
    return containerManager2.getEnvironmentStatus();
  });
  electron.ipcMain.handle(IPC_CHANNELS.ENV_CREATE, async (_event, token, rawConfig) => {
    requireElevatedSession(token, sessionManager2);
    const config = validateStackConfig(rawConfig);
    await orchestrator.up(config);
  });
  electron.ipcMain.handle(IPC_CHANNELS.ENV_START, async (_event, token) => {
    requireSession(token, sessionManager2);
    await containerManager2.startEnvironment();
  });
  electron.ipcMain.handle(IPC_CHANNELS.ENV_STOP, async (_event, token) => {
    requireSession(token, sessionManager2);
    await containerManager2.stopEnvironment();
  });
  electron.ipcMain.handle(IPC_CHANNELS.ENV_DESTROY, async (_event, token) => {
    requireElevatedSession(token, sessionManager2);
    await orchestrator.down();
  });
  electron.ipcMain.handle(IPC_CHANNELS.ENV_LOGS, async (_event, token, containerId) => {
    requireSession(token, sessionManager2);
    if (typeof containerId !== "string") {
      return "";
    }
    return dockerClient2.getContainerLogs(containerId, { tail: 200 });
  });
  electron.ipcMain.handle(IPC_CHANNELS.SYSTEM_VALIDATE, async () => {
    const dockerInfo = await detector.detect();
    const checks = [];
    checks.push({
      name: "Container Engine",
      description: "Docker or compatible engine is installed and running",
      result: dockerInfo.running ? "pass" : "fail",
      message: dockerInfo.running ? `${dockerInfo.variant} v${dockerInfo.version} detected` : "No container engine detected. Install Docker Desktop or Docker CE.",
      autoFixAvailable: !dockerInfo.running
    });
    const os$1 = process.platform;
    const supported = ["darwin", "win32", "linux"].includes(os$1);
    checks.push({
      name: "Operating System",
      description: "Compatible operating system",
      result: supported ? "pass" : "fail",
      message: supported ? `${os$1} is supported` : `${os$1} is not supported`,
      autoFixAvailable: false
    });
    const nodeVersion = process.versions.node;
    const [major] = nodeVersion.split(".").map(Number);
    checks.push({
      name: "Node.js Runtime",
      description: "Node.js 22.12.0 or later",
      result: major >= 22 ? "pass" : "fail",
      message: major >= 22 ? `Node.js v${nodeVersion}` : `Node.js v${nodeVersion} — upgrade to v22.12.0+`,
      autoFixAvailable: false
    });
    const totalMemGB = Math.round(os.totalmem() / 1024 / 1024 / 1024 * 10) / 10;
    checks.push({
      name: "Available Memory",
      description: "At least 4 GB RAM recommended",
      result: totalMemGB >= 4 ? "pass" : "warn",
      message: `${totalMemGB} GB total RAM`,
      autoFixAvailable: false
    });
    const allPassed = checks.every((c) => c.result === "pass");
    const canProceed = checks.every((c) => c.result !== "fail");
    return { checks, allPassed, canProceed };
  });
  electron.ipcMain.handle(IPC_CHANNELS.SYSTEM_PLATFORM, async () => {
    return {
      os: process.platform,
      arch: process.arch,
      version: process.version
    };
  });
  electron.ipcMain.handle(IPC_CHANNELS.CONFIG_SECTIONS, async (_event, token) => {
    requireSession(token, sessionManager2);
    return [];
  });
  electron.ipcMain.handle(IPC_CHANNELS.CONFIG_GET, async (_event, token, _section) => {
    requireSession(token, sessionManager2);
    return {};
  });
  electron.ipcMain.handle(IPC_CHANNELS.SKILLS_LIST, async (_event, token) => {
    requireSession(token, sessionManager2);
    return [];
  });
}
class DockerEngineClient {
  docker;
  constructor(socketPath) {
    this.docker = new Dockerode(
      socketPath ? { socketPath } : void 0
    );
  }
  /** @internal Raw dockerode instance — not for external callers. */
  getEngine() {
    return this.docker;
  }
  /** Ping the Docker daemon to check connectivity. */
  async ping() {
    try {
      await this.docker.ping();
      return true;
    } catch {
      return false;
    }
  }
  /** Get Docker system info. */
  async info() {
    return this.docker.info();
  }
  /** List all containers (running and stopped). */
  async listContainers(all = true) {
    return this.docker.listContainers({ all });
  }
  /** Get a container by ID. */
  getContainer(id) {
    return this.docker.getContainer(id);
  }
  /** Inspect a container for detailed info. */
  async inspectContainer(id) {
    return this.docker.getContainer(id).inspect();
  }
  /** Start a container. */
  async startContainer(id) {
    await this.docker.getContainer(id).start();
  }
  /** Stop a container gracefully. */
  async stopContainer(id, timeout = 10) {
    await this.docker.getContainer(id).stop({ t: timeout });
  }
  /** Remove a container. */
  async removeContainer(id, force = false) {
    await this.docker.getContainer(id).remove({ force, v: true });
  }
  /** Get real-time container stats. */
  async getContainerStats(id) {
    return this.docker.getContainer(id).stats({ stream: false });
  }
  /** Pull an image by name. Returns a progress stream. */
  async pullImage(imageName) {
    return this.docker.pull(imageName);
  }
  /** Build an image from a Dockerfile context. */
  async buildImage(context, options) {
    return this.docker.buildImage(
      { context, src: ["."] },
      {
        dockerfile: options.dockerfile ?? "Dockerfile",
        t: options.t,
        buildargs: options.buildargs
      }
    );
  }
  /** List all images. */
  async listImages() {
    return this.docker.listImages();
  }
  /** Check if an image exists locally. */
  async imageExists(name) {
    try {
      await this.docker.getImage(name).inspect();
      return true;
    } catch {
      return false;
    }
  }
  /** Create a Docker network. */
  async createNetwork(name) {
    return this.docker.createNetwork({
      Name: name,
      Driver: "bridge",
      CheckDuplicate: true,
      // Prevent silent duplicate network creation
      Internal: false,
      Labels: { "ai.openclaw.managed": "true" }
    });
  }
  /** List networks managed by OCCC. */
  async listManagedNetworks() {
    const networks = await this.docker.listNetworks({
      filters: { label: ["ai.openclaw.managed=true"] }
    });
    return networks;
  }
  /** Create a named volume for persistent data. */
  async createVolume(name) {
    return this.docker.createVolume({
      Name: name,
      Labels: { "ai.openclaw.managed": "true" }
    });
  }
  /** List volumes managed by OCCC. */
  async listManagedVolumes() {
    const result = await this.docker.listVolumes({
      filters: { label: ["ai.openclaw.managed=true"] }
    });
    return result.Volumes ?? [];
  }
  /** Remove a network by ID. */
  async removeNetwork(id) {
    await this.docker.getNetwork(id).remove();
  }
  /** Remove a named volume. */
  async removeVolume(name) {
    await this.docker.getVolume(name).remove({});
  }
  /** Inspect an image by name/tag. */
  async inspectImage(name) {
    return this.docker.getImage(name).inspect();
  }
  /** Remove an image by name. */
  async removeImage(name, force = false) {
    await this.docker.getImage(name).remove({ force });
  }
  /**
   * Follow a Docker modem progress stream.
   * Calls onEnd when the stream finishes; relays each event to onEvent.
   */
  followStreamProgress(stream, onEnd, onEvent) {
    this.docker.modem.followProgress(
      stream,
      (err) => onEnd(err),
      onEvent
    );
  }
  /** Create and start a container with security hardening. */
  async createContainer(options) {
    const portBindings = {};
    const exposedPorts = {};
    if (options.ports) {
      for (const [containerPort, hostPort] of Object.entries(options.ports)) {
        const key = `${containerPort}/tcp`;
        portBindings[key] = [{ HostPort: String(hostPort) }];
        exposedPorts[key] = {};
      }
    }
    const binds = [];
    if (options.volumes) {
      for (const [hostPath, containerPath] of Object.entries(options.volumes)) {
        binds.push(`${hostPath}:${containerPath}`);
      }
    }
    const container = await this.docker.createContainer({
      name: options.name,
      Image: options.image,
      Cmd: options.cmd,
      Env: options.env,
      ExposedPorts: exposedPorts,
      Labels: {
        "ai.openclaw.managed": "true",
        ...options.labels
      },
      HostConfig: {
        PortBindings: portBindings,
        Binds: binds,
        NetworkMode: options.network,
        // Security hardening (non-root, capabilities dropped)
        Init: true,
        RestartPolicy: { Name: "unless-stopped" },
        CapDrop: ["ALL"],
        SecurityOpt: ["no-new-privileges:true"],
        ReadonlyRootfs: false
        // OpenClaw needs writable /tmp
      },
      // Security: run as non-root user (node, uid 1000)
      User: "1000:1000"
    });
    return container;
  }
  /** Get logs from a container. */
  async getContainerLogs(id, options = {}) {
    const logs = await this.docker.getContainer(id).logs({
      stdout: true,
      stderr: true,
      tail: options.tail ?? 100,
      since: options.since,
      timestamps: true
    });
    return logs.toString();
  }
}
const LABELS = {
  managed: "ai.openclaw.managed",
  role: "ai.openclaw.role"
};
function roleLabel(role) {
  return {
    [LABELS.managed]: "true",
    [LABELS.role]: role
  };
}
class ContainerManager {
  constructor(client) {
    this.client = client;
  }
  // ─── Environment Lifecycle ──────────────────────────────────────────────
  /**
   * Create the gateway container and attach it to an existing network.
   *
   * Network and volume creation are the caller's responsibility (use
   * ComposeOrchestrator.up() or InstallerEngine.install() which call
   * NetworkManager/VolumeManager before this). Separating concerns prevents
   * double-creation errors when the orchestrator already ensured them.
   */
  async createEnvironment(config) {
    const image = config.image ?? OPENCLAW_IMAGE;
    const gatewayPort = config.gatewayPort ?? DEFAULT_GATEWAY_PORT;
    const bridgePort = config.bridgePort ?? DEFAULT_BRIDGE_PORT;
    const network = config.network ?? "openclaw-net";
    const gateway = await this.client.createContainer({
      name: "openclaw-gateway",
      image,
      cmd: [
        "node",
        "dist/index.js",
        "gateway",
        "--bind",
        "lan",
        "--port",
        String(gatewayPort)
      ],
      env: [
        "HOME=/home/node",
        "TERM=xterm-256color",
        `OPENCLAW_GATEWAY_TOKEN=${config.gatewayToken}`,
        "NODE_ENV=production"
      ],
      ports: {
        [String(gatewayPort)]: gatewayPort,
        [String(bridgePort)]: bridgePort
      },
      volumes: {
        [config.configDir]: "/home/node/.openclaw",
        [config.workspaceDir]: "/home/node/.openclaw/workspace"
      },
      network,
      labels: roleLabel("gateway")
    });
    await gateway.start();
  }
  /**
   * Start all stopped OCCC-managed containers.
   */
  async startEnvironment() {
    const managed = await this.getManagedContainers();
    for (const c of managed) {
      if (c.State !== "running") {
        await this.client.startContainer(c.Id);
      }
    }
  }
  /**
   * Stop all running OCCC-managed containers gracefully.
   */
  async stopEnvironment() {
    const managed = await this.getManagedContainers();
    for (const c of managed) {
      if (c.State === "running") {
        await this.client.stopContainer(c.Id);
      }
    }
  }
  /**
   * Destroy the entire environment — stops, removes containers, network, volumes.
   */
  async destroyEnvironment() {
    const managed = await this.getManagedContainers();
    for (const c of managed) {
      await this.client.removeContainer(c.Id, true);
    }
    const networks = await this.client.listManagedNetworks();
    for (const net of networks) {
      await this.client.removeNetwork(net.Id);
    }
  }
  // ─── Status ─────────────────────────────────────────────────────────────
  /**
   * Get the aggregate status of the OpenClaw environment.
   */
  async getEnvironmentStatus() {
    const managed = await this.getManagedContainers();
    let gateway = null;
    let cli = null;
    const sandboxes = [];
    for (const c of managed) {
      const status = await this.buildContainerStatus(c);
      const role = c.Labels?.[LABELS.role];
      if (role === "gateway") {
        gateway = status;
      } else if (role === "cli") {
        cli = status;
      } else if (role === "sandbox") {
        sandboxes.push(status);
      }
    }
    const defaultStopped = {
      id: "",
      name: "Not Created",
      state: "stopped",
      health: "stopped",
      cpu: 0,
      memoryMB: 0,
      networkRx: 0,
      networkTx: 0
    };
    const gw = gateway ?? defaultStopped;
    const cl = cli ?? defaultStopped;
    const health = this.aggregateHealth(gw, cl, sandboxes);
    let uptime = null;
    if (gw.id && gw.state === "running") {
      try {
        const inspect = await this.client.inspectContainer(gw.id);
        const startedAt = inspect.State?.StartedAt;
        if (startedAt) {
          uptime = Date.now() - new Date(startedAt).getTime();
        }
      } catch {
      }
    }
    return { health, gateway: gw, cli: cl, sandboxes, uptime };
  }
  // ─── Helpers ────────────────────────────────────────────────────────────
  async getManagedContainers() {
    const all = await this.client.listContainers(true);
    return all.filter(
      (c) => c.Labels?.[LABELS.managed] === "true"
    );
  }
  async buildContainerStatus(c) {
    const name = (c.Names?.[0] ?? "").replace(/^\//, "");
    let cpu = 0;
    let memoryMB = 0;
    let networkRx = 0;
    let networkTx = 0;
    if (c.State === "running") {
      try {
        const stats = await this.client.getContainerStats(c.Id);
        cpu = this.calculateCpuPercent(stats);
        memoryMB = Math.round((stats.memory_stats?.usage ?? 0) / 1024 / 1024);
        const netStats = Object.values(stats.networks ?? {})[0];
        networkRx = netStats?.rx_bytes ?? 0;
        networkTx = netStats?.tx_bytes ?? 0;
      } catch {
      }
    }
    const state = c.State ?? "unknown";
    const health = state === "running" ? "healthy" : state === "dead" ? "unhealthy" : "stopped";
    return { id: c.Id, name, state, health, cpu, memoryMB, networkRx, networkTx };
  }
  calculateCpuPercent(stats) {
    const cpuStats = stats.cpu_stats;
    const precpuStats = stats.precpu_stats;
    const cpuDelta = (cpuStats?.cpu_usage?.total_usage ?? 0) - (precpuStats?.cpu_usage?.total_usage ?? 0);
    const systemDelta = (cpuStats?.system_cpu_usage ?? 0) - (precpuStats?.system_cpu_usage ?? 0);
    const numCpus = cpuStats?.online_cpus ?? 1;
    if (systemDelta > 0 && cpuDelta > 0) {
      return Math.round(cpuDelta / systemDelta * numCpus * 100 * 100) / 100;
    }
    return 0;
  }
  aggregateHealth(gateway, cli, sandboxes) {
    if (gateway.health === "unhealthy") {
      return "unhealthy";
    }
    if (gateway.health === "stopped") {
      return "stopped";
    }
    if (sandboxes.some((s) => s.health === "unhealthy")) {
      return "degraded";
    }
    if (gateway.health === "healthy") {
      return "healthy";
    }
    return "unknown";
  }
}
const DB_VERSION = 1;
class AuthStore {
  db = null;
  encKey = null;
  /**
   * Initialize the database and encryption key.
   * The encryption key is derived from a machine-specific secret.
   */
  async init() {
    const { scryptSync } = await import("node:crypto");
    const machineId = await this.getMachineId();
    const salt = "occc-auth-v1";
    this.encKey = scryptSync(machineId, salt, 32);
    const Database = (await import("better-sqlite3")).default;
    const dbPath = path.join(electron.app.getPath("userData"), "auth.db");
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");
    this.migrate();
  }
  migrate() {
    if (!this.db) {
      throw new Error("DB not initialized");
    }
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);
    const versionRow = this.db.prepare("SELECT value FROM meta WHERE key = 'version'").get();
    if (!versionRow) {
      this.db.prepare("INSERT INTO meta (key, value) VALUES ('version', ?)").run(String(DB_VERSION));
    }
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL COLLATE NOCASE,
        role TEXT NOT NULL CHECK(role IN ('super-admin', 'admin', 'operator', 'viewer')),
        password_hash TEXT NOT NULL,
        totp_secret_enc TEXT NOT NULL DEFAULT '',
        totp_enabled INTEGER NOT NULL DEFAULT 0,
        biometric_enrolled INTEGER NOT NULL DEFAULT 0,
        recovery_codes_enc TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        last_login_at TEXT
      );
    `);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS auth_audit (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        event TEXT NOT NULL,
        method TEXT,
        success INTEGER NOT NULL,
        ip_hint TEXT,
        timestamp TEXT NOT NULL
      );
    `);
  }
  /** Check if any users exist (first-run detection). */
  hasUsers() {
    if (!this.db) {
      return false;
    }
    const row = this.db.prepare("SELECT COUNT(*) as count FROM users").get();
    return row.count > 0;
  }
  /** Get a user by username. */
  getUserByUsername(username) {
    if (!this.db) {
      return null;
    }
    return this.db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  }
  /** Get a user by ID. */
  getUserById(id) {
    if (!this.db) {
      return null;
    }
    return this.db.prepare("SELECT * FROM users WHERE id = ?").get(id);
  }
  /** List all users (for admin panel). */
  listUsers() {
    if (!this.db) {
      return [];
    }
    const rows = this.db.prepare("SELECT * FROM users ORDER BY created_at").all();
    return rows.map((r) => this.rowToProfile(r));
  }
  /** Create a new user. Returns the created profile. */
  async createUser(params) {
    if (!this.db) {
      throw new Error("DB not initialized");
    }
    const { argon2id } = await Promise.resolve().then(() => require("./index.esm-DMNGx1ys.cjs"));
    const id = node_crypto.randomBytes(16).toString("hex");
    const salt = node_crypto.randomBytes(16);
    const hash = await argon2id({
      password: params.password,
      salt,
      iterations: 3,
      parallelism: 4,
      memorySize: 65536,
      // 64 MB
      hashLength: 32,
      outputType: "hex"
    });
    const passwordHash = `argon2id$${salt.toString("hex")}$${hash}`;
    const totpSecretEnc = params.totpSecret ? this.encrypt(params.totpSecret) : "";
    const now = (/* @__PURE__ */ new Date()).toISOString();
    this.db.prepare(`
      INSERT INTO users (id, username, role, password_hash, totp_secret_enc, totp_enabled, biometric_enrolled, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, params.username, params.role, passwordHash, totpSecretEnc, totpSecretEnc ? 1 : 0, 0, now);
    this.auditLog({ event: "user_created", userId: id, method: "admin", success: true });
    return {
      id,
      username: params.username,
      role: params.role,
      biometricEnrolled: false,
      totpEnabled: !!params.totpSecret,
      createdAt: now,
      lastLoginAt: null
    };
  }
  /** Verify a password against the stored hash. */
  async verifyPassword(userId, password) {
    const user = this.getUserById(userId);
    if (!user) {
      return false;
    }
    try {
      const [algo, saltHex, storedHash] = user.password_hash.split("$");
      if (algo !== "argon2id") {
        return false;
      }
      const { argon2id } = await Promise.resolve().then(() => require("./index.esm-DMNGx1ys.cjs"));
      const salt = Buffer.from(saltHex, "hex");
      const computed = await argon2id({
        password,
        salt,
        iterations: 3,
        parallelism: 4,
        memorySize: 65536,
        hashLength: 32,
        outputType: "hex"
      });
      return node_crypto.timingSafeEqual(
        Buffer.from(computed, "hex"),
        Buffer.from(storedHash, "hex")
      );
    } catch {
      return false;
    }
  }
  /** Get the TOTP secret for a user (decrypted). */
  getTotpSecret(userId) {
    const user = this.getUserById(userId);
    if (!user || !user.totp_secret_enc) {
      return null;
    }
    try {
      return this.decrypt(user.totp_secret_enc);
    } catch {
      return null;
    }
  }
  /** Mark biometric as enrolled for a user. */
  setBiometricEnrolled(userId, enrolled) {
    this.db?.prepare("UPDATE users SET biometric_enrolled = ? WHERE id = ?").run(enrolled ? 1 : 0, userId);
  }
  /** Update last login timestamp. */
  updateLastLogin(userId) {
    this.db?.prepare("UPDATE users SET last_login_at = ? WHERE id = ?").run((/* @__PURE__ */ new Date()).toISOString(), userId);
  }
  /** Write an audit log entry. */
  auditLog(entry) {
    if (!this.db) {
      return;
    }
    this.db.prepare(`
      INSERT INTO auth_audit (id, user_id, event, method, success, ip_hint, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      node_crypto.randomBytes(8).toString("hex"),
      entry.userId ?? null,
      entry.event,
      entry.method ?? null,
      entry.success ? 1 : 0,
      entry.ipHint ?? null,
      (/* @__PURE__ */ new Date()).toISOString()
    );
  }
  /** Persist a TOTP secret (encrypted) and mark totp_enabled = 1. */
  setTotpSecret(userId, secret) {
    if (!this.db) {
      throw new Error("DB not initialized");
    }
    const encrypted = this.encrypt(secret);
    this.db.prepare("UPDATE users SET totp_secret_enc = ?, totp_enabled = 1 WHERE id = ?").run(encrypted, userId);
  }
  // ─── Recovery Codes ───────────────────────────────────────────────────
  /** Hash a recovery code for storage (SHA-256 hex). */
  hashRecoveryCode(code) {
    return node_crypto.createHash("sha256").update(code.toUpperCase().replace(/-/g, "")).digest("hex");
  }
  /** Store recovery codes (encrypted). Hashes each code for one-time-use verification. */
  async setRecoveryCodes(userId, codes) {
    if (!this.db) {
      throw new Error("DB not initialized");
    }
    const hashes = codes.map((c) => this.hashRecoveryCode(c));
    const encrypted = this.encrypt(JSON.stringify(hashes));
    this.db.prepare("UPDATE users SET recovery_codes_enc = ? WHERE id = ?").run(encrypted, userId);
  }
  /** Try a recovery code. Returns true and consumes the code if valid. */
  async useRecoveryCode(userId, code) {
    if (!this.db) {
      return false;
    }
    const user = this.getUserById(userId);
    if (!user || !user.recovery_codes_enc) {
      return false;
    }
    let hashes;
    try {
      hashes = JSON.parse(this.decrypt(user.recovery_codes_enc));
    } catch {
      return false;
    }
    const inputHash = this.hashRecoveryCode(code);
    const inputBuf = Buffer.from(inputHash, "hex");
    const idx = hashes.findIndex(
      (h) => node_crypto.timingSafeEqual(Buffer.from(h, "hex"), inputBuf)
    );
    if (idx === -1) {
      return false;
    }
    hashes.splice(idx, 1);
    const encrypted = this.encrypt(JSON.stringify(hashes));
    this.db.prepare("UPDATE users SET recovery_codes_enc = ? WHERE id = ?").run(encrypted, userId);
    this.auditLog({ event: "recovery_code_used", userId, method: "recovery", success: true });
    return true;
  }
  /** Get a user DB row (internal use for auth-engine). */
  // Note: exposed as a method so auth-engine can read totp_enabled, biometric_enrolled
  getUserRowById(id) {
    return this.getUserById(id);
  }
  /** Delete a user by ID. Returns false if user not found or is the last super-admin. */
  deleteUser(userId) {
    if (!this.db) {
      return { ok: false, reason: "DB not initialized" };
    }
    const user = this.getUserById(userId);
    if (!user) {
      return { ok: false, reason: "User not found" };
    }
    if (user.role === "super-admin") {
      const row = this.db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'super-admin'").get();
      if (row.count <= 1) {
        return { ok: false, reason: "Cannot delete the last super-admin account" };
      }
    }
    this.db.prepare("DELETE FROM users WHERE id = ?").run(userId);
    this.auditLog({ event: "user_deleted", userId, method: "admin", success: true });
    return { ok: true };
  }
  /** Update a user's role. Returns false if target role is invalid or would remove last super-admin. */
  updateUserRole(userId, newRole) {
    if (!this.db) {
      return { ok: false, reason: "DB not initialized" };
    }
    const user = this.getUserById(userId);
    if (!user) {
      return { ok: false, reason: "User not found" };
    }
    if (user.role === "super-admin" && newRole !== "super-admin") {
      const row = this.db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'super-admin'").get();
      if (row.count <= 1) {
        return { ok: false, reason: "Cannot demote the last super-admin account" };
      }
    }
    this.db.prepare("UPDATE users SET role = ? WHERE id = ?").run(newRole, userId);
    this.auditLog({ event: "role_changed", userId, method: `admin→${newRole}`, success: true });
    return { ok: true };
  }
  /** Reset a user's password (admin-initiated). Invalidates existing sessions. */
  async resetPassword(userId, newPassword) {
    if (!this.db) {
      return { ok: false, reason: "DB not initialized" };
    }
    const user = this.getUserById(userId);
    if (!user) {
      return { ok: false, reason: "User not found" };
    }
    try {
      const { argon2id } = await Promise.resolve().then(() => require("./index.esm-DMNGx1ys.cjs"));
      const salt = node_crypto.randomBytes(16);
      const hash = await argon2id({
        password: newPassword,
        salt,
        iterations: 3,
        parallelism: 4,
        memorySize: 65536,
        hashLength: 32,
        outputType: "hex"
      });
      const passwordHash = `argon2id$${salt.toString("hex")}$${hash}`;
      this.db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(passwordHash, userId);
      this.auditLog({ event: "password_reset", userId, method: "admin", success: true });
      return { ok: true };
    } catch (err) {
      return { ok: false, reason: err instanceof Error ? err.message : "Hashing failed" };
    }
  }
  /** Read audit log entries (most recent first). */
  getAuditLog(limit = 100) {
    if (!this.db) {
      return [];
    }
    const rows = this.db.prepare(
      `SELECT a.id, a.user_id as userId, a.event, a.method, a.success, a.timestamp,
                u.username
         FROM auth_audit a
         LEFT JOIN users u ON a.user_id = u.id
         ORDER BY a.timestamp DESC
         LIMIT ?`
    ).all(limit);
    return rows.map((r) => ({
      id: r.id,
      userId: r.userId,
      username: r.username ?? null,
      event: r.event,
      method: r.method,
      success: r.success === 1,
      timestamp: r.timestamp
    }));
  }
  // ─── Encryption helpers (AES-256-GCM) ────────────────────────────────
  encrypt(plaintext) {
    if (!this.encKey) {
      throw new Error("Encryption key not initialized");
    }
    const iv = node_crypto.randomBytes(12);
    const cipher = node_crypto.createCipheriv("aes-256-gcm", this.encKey, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${iv.toString("hex")}:${tag.toString("hex")}:${encrypted.toString("base64")}`;
  }
  decrypt(encoded) {
    if (!this.encKey) {
      throw new Error("Encryption key not initialized");
    }
    const [ivHex, tagHex, ciphertextB64] = encoded.split(":");
    const iv = Buffer.from(ivHex, "hex");
    const tag = Buffer.from(tagHex, "hex");
    const ciphertext = Buffer.from(ciphertextB64, "base64");
    const decipher = node_crypto.createDecipheriv("aes-256-gcm", this.encKey, iv);
    decipher.setAuthTag(tag);
    return decipher.update(ciphertext).toString("utf8") + decipher.final("utf8");
  }
  // ─── Machine ID ───────────────────────────────────────────────────────
  async getMachineId() {
    const os2 = await import("node:os");
    const hostname = os2.hostname();
    const username = os2.userInfo().username;
    const homedir = os2.homedir();
    return node_crypto.createHmac("sha256", "occc-machine-key").update(`${hostname}:${username}:${homedir}`).digest("hex");
  }
  rowToProfile(row) {
    return {
      id: row.id,
      username: row.username,
      role: row.role,
      biometricEnrolled: row.biometric_enrolled === 1,
      totpEnabled: row.totp_enabled === 1,
      createdAt: row.created_at,
      lastLoginAt: row.last_login_at
    };
  }
}
const ELEVATED_SESSION_DURATION_MS = 5 * 60 * 1e3;
class SessionManager {
  sessions = /* @__PURE__ */ new Map();
  signingKey = node_crypto.randomBytes(32);
  // In-memory, rotated on app restart
  cleanupInterval;
  constructor() {
    this.cleanupInterval = setInterval(() => this.pruneExpired(), 6e4);
  }
  // ─── Session Lifecycle ───────────────────────────────────────────────
  /** Create a new normal session after successful login. */
  createSession(userId, role) {
    const now = Date.now();
    const sessionId = node_crypto.randomBytes(16).toString("hex");
    const session = {
      userId,
      role,
      authenticatedAt: now,
      expiresAt: now + AUTH_SESSION_TIMEOUT_MS,
      elevated: false
    };
    const token = this.signToken(sessionId);
    this.sessions.set(sessionId, { session, token, lastActivity: now });
    return { session, token };
  }
  /** Elevate an existing session (after biometric/TOTP re-auth). */
  elevateSession(token) {
    const entry = this.resolveToken(token);
    if (!entry) {
      return false;
    }
    entry.session.elevated = true;
    entry.session.expiresAt = Date.now() + ELEVATED_SESSION_DURATION_MS;
    entry.lastActivity = Date.now();
    return true;
  }
  /** Drop elevation (call after a sensitive operation completes). */
  dropElevation(token) {
    const entry = this.resolveToken(token);
    if (!entry) {
      return;
    }
    entry.session.elevated = false;
    entry.session.expiresAt = Date.now() + AUTH_SESSION_TIMEOUT_MS;
  }
  /** Invalidate (log out) a session. */
  invalidate(token) {
    const sessionId = this.extractSessionId(token);
    if (sessionId) {
      this.sessions.delete(sessionId);
    }
  }
  /** Invalidate all sessions for a user (e.g., on role change or account deletion). */
  invalidateAllForUser(userId) {
    for (const [id, entry] of this.sessions) {
      if (entry.session.userId === userId) {
        this.sessions.delete(id);
      }
    }
  }
  // ─── Session Resolution ──────────────────────────────────────────────
  /** Resolve a token to its session, refreshing the idle timer. Returns null if invalid. */
  resolve(token) {
    const entry = this.resolveToken(token);
    if (!entry) {
      return null;
    }
    if (!entry.session.elevated) {
      entry.session.expiresAt = Date.now() + AUTH_SESSION_TIMEOUT_MS;
    }
    entry.lastActivity = Date.now();
    return { ...entry.session };
  }
  /** Check if a token is valid without refreshing the idle timer. */
  isValid(token) {
    return this.resolveToken(token) !== null;
  }
  // ─── Helpers ─────────────────────────────────────────────────────────
  resolveToken(token) {
    const sessionId = this.extractSessionId(token);
    if (!sessionId) {
      return null;
    }
    const entry = this.sessions.get(sessionId);
    if (!entry) {
      return null;
    }
    if (!node_crypto.timingSafeEqual(Buffer.from(entry.token), Buffer.from(token))) {
      return null;
    }
    if (Date.now() > entry.session.expiresAt) {
      this.sessions.delete(sessionId);
      return null;
    }
    return entry;
  }
  /**
   * Token format: "<sessionId_hex>.<hmac_hex>"
   * HMAC is over the sessionId, signed with the in-memory key.
   */
  signToken(sessionId) {
    const hmac = node_crypto.createHmac("sha256", this.signingKey).update(sessionId).digest("hex");
    return `${sessionId}.${hmac}`;
  }
  extractSessionId(token) {
    const [sessionId] = token.split(".");
    if (!sessionId) {
      return null;
    }
    const expected = this.signToken(sessionId);
    try {
      if (node_crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(token))) {
        return sessionId;
      }
    } catch {
    }
    return null;
  }
  pruneExpired() {
    const now = Date.now();
    for (const [id, entry] of this.sessions) {
      if (now > entry.session.expiresAt) {
        this.sessions.delete(id);
      }
    }
  }
  destroy() {
    clearInterval(this.cleanupInterval);
    this.sessions.clear();
  }
}
var otplib = {};
var presetDefault = {};
var pluginCrypto = {};
var hasRequiredPluginCrypto;
function requirePluginCrypto() {
  if (hasRequiredPluginCrypto) return pluginCrypto;
  hasRequiredPluginCrypto = 1;
  Object.defineProperty(pluginCrypto, "__esModule", { value: true });
  function _interopDefault(ex) {
    return ex && typeof ex === "object" && "default" in ex ? ex["default"] : ex;
  }
  var crypto = _interopDefault(require$$0);
  const createDigest = (algorithm, hmacKey, counter) => {
    const hmac = crypto.createHmac(algorithm, Buffer.from(hmacKey, "hex"));
    const digest = hmac.update(Buffer.from(counter, "hex")).digest();
    return digest.toString("hex");
  };
  const createRandomBytes = (size, encoding) => {
    return crypto.randomBytes(size).toString(encoding);
  };
  pluginCrypto.createDigest = createDigest;
  pluginCrypto.createRandomBytes = createRandomBytes;
  return pluginCrypto;
}
var pluginThirtyTwo = {};
var thirtyTwo$1 = {};
var thirtyTwo = {};
var hasRequiredThirtyTwo$1;
function requireThirtyTwo$1() {
  if (hasRequiredThirtyTwo$1) return thirtyTwo;
  hasRequiredThirtyTwo$1 = 1;
  var charTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  var byteTable = [
    255,
    255,
    26,
    27,
    28,
    29,
    30,
    31,
    255,
    255,
    255,
    255,
    255,
    255,
    255,
    255,
    255,
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16,
    17,
    18,
    19,
    20,
    21,
    22,
    23,
    24,
    25,
    255,
    255,
    255,
    255,
    255,
    255,
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16,
    17,
    18,
    19,
    20,
    21,
    22,
    23,
    24,
    25,
    255,
    255,
    255,
    255,
    255
  ];
  function quintetCount(buff) {
    var quintets = Math.floor(buff.length / 5);
    return buff.length % 5 === 0 ? quintets : quintets + 1;
  }
  thirtyTwo.encode = function(plain) {
    if (!Buffer.isBuffer(plain)) {
      plain = new Buffer(plain);
    }
    var i = 0;
    var j = 0;
    var shiftIndex = 0;
    var digit = 0;
    var encoded = new Buffer(quintetCount(plain) * 8);
    while (i < plain.length) {
      var current = plain[i];
      if (shiftIndex > 3) {
        digit = current & 255 >> shiftIndex;
        shiftIndex = (shiftIndex + 5) % 8;
        digit = digit << shiftIndex | (i + 1 < plain.length ? plain[i + 1] : 0) >> 8 - shiftIndex;
        i++;
      } else {
        digit = current >> 8 - (shiftIndex + 5) & 31;
        shiftIndex = (shiftIndex + 5) % 8;
        if (shiftIndex === 0) i++;
      }
      encoded[j] = charTable.charCodeAt(digit);
      j++;
    }
    for (i = j; i < encoded.length; i++) {
      encoded[i] = 61;
    }
    return encoded;
  };
  thirtyTwo.decode = function(encoded) {
    var shiftIndex = 0;
    var plainDigit = 0;
    var plainChar;
    var plainPos = 0;
    if (!Buffer.isBuffer(encoded)) {
      encoded = new Buffer(encoded);
    }
    var decoded = new Buffer(Math.ceil(encoded.length * 5 / 8));
    for (var i = 0; i < encoded.length; i++) {
      if (encoded[i] === 61) {
        break;
      }
      var encodedByte = encoded[i] - 48;
      if (encodedByte < byteTable.length) {
        plainDigit = byteTable[encodedByte];
        if (shiftIndex <= 3) {
          shiftIndex = (shiftIndex + 5) % 8;
          if (shiftIndex === 0) {
            plainChar |= plainDigit;
            decoded[plainPos] = plainChar;
            plainPos++;
            plainChar = 0;
          } else {
            plainChar |= 255 & plainDigit << 8 - shiftIndex;
          }
        } else {
          shiftIndex = (shiftIndex + 5) % 8;
          plainChar |= 255 & plainDigit >>> shiftIndex;
          decoded[plainPos] = plainChar;
          plainPos++;
          plainChar = 255 & plainDigit << 8 - shiftIndex;
        }
      } else {
        throw new Error("Invalid input - it is not base32 encoded string");
      }
    }
    return decoded.slice(0, plainPos);
  };
  return thirtyTwo;
}
var hasRequiredThirtyTwo;
function requireThirtyTwo() {
  if (hasRequiredThirtyTwo) return thirtyTwo$1;
  hasRequiredThirtyTwo = 1;
  var base32 = requireThirtyTwo$1();
  thirtyTwo$1.encode = base32.encode;
  thirtyTwo$1.decode = base32.decode;
  return thirtyTwo$1;
}
var hasRequiredPluginThirtyTwo;
function requirePluginThirtyTwo() {
  if (hasRequiredPluginThirtyTwo) return pluginThirtyTwo;
  hasRequiredPluginThirtyTwo = 1;
  Object.defineProperty(pluginThirtyTwo, "__esModule", { value: true });
  function _interopDefault(ex) {
    return ex && typeof ex === "object" && "default" in ex ? ex["default"] : ex;
  }
  var thirtyTwo2 = _interopDefault(requireThirtyTwo());
  const keyDecoder = (encodedSecret, encoding) => {
    return thirtyTwo2.decode(encodedSecret).toString(encoding);
  };
  const keyEncoder = (secret, encoding) => {
    return thirtyTwo2.encode(Buffer.from(secret, encoding).toString("ascii")).toString().replace(/=/g, "");
  };
  pluginThirtyTwo.keyDecoder = keyDecoder;
  pluginThirtyTwo.keyEncoder = keyEncoder;
  return pluginThirtyTwo;
}
var core = {};
var hasRequiredCore;
function requireCore() {
  if (hasRequiredCore) return core;
  hasRequiredCore = 1;
  (function(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    function objectValues(value) {
      return Object.keys(value).map((key) => value[key]);
    }
    (function(HashAlgorithms) {
      HashAlgorithms["SHA1"] = "sha1";
      HashAlgorithms["SHA256"] = "sha256";
      HashAlgorithms["SHA512"] = "sha512";
    })(exports$1.HashAlgorithms || (exports$1.HashAlgorithms = {}));
    const HASH_ALGORITHMS = objectValues(exports$1.HashAlgorithms);
    (function(KeyEncodings) {
      KeyEncodings["ASCII"] = "ascii";
      KeyEncodings["BASE64"] = "base64";
      KeyEncodings["HEX"] = "hex";
      KeyEncodings["LATIN1"] = "latin1";
      KeyEncodings["UTF8"] = "utf8";
    })(exports$1.KeyEncodings || (exports$1.KeyEncodings = {}));
    const KEY_ENCODINGS = objectValues(exports$1.KeyEncodings);
    (function(Strategy) {
      Strategy["HOTP"] = "hotp";
      Strategy["TOTP"] = "totp";
    })(exports$1.Strategy || (exports$1.Strategy = {}));
    const STRATEGY = objectValues(exports$1.Strategy);
    const createDigestPlaceholder = () => {
      throw new Error("Please provide an options.createDigest implementation.");
    };
    function isTokenValid(value) {
      return /^(\d+)$/.test(value);
    }
    function padStart(value, maxLength, fillString) {
      if (value.length >= maxLength) {
        return value;
      }
      const padding = Array(maxLength + 1).join(fillString);
      return `${padding}${value}`.slice(-1 * maxLength);
    }
    function keyuri(options) {
      const tmpl = `otpauth://${options.type}/{labelPrefix}:{accountName}?secret={secret}{query}`;
      const params = [];
      if (STRATEGY.indexOf(options.type) < 0) {
        throw new Error(`Expecting options.type to be one of ${STRATEGY.join(", ")}. Received ${options.type}.`);
      }
      if (options.type === "hotp") {
        if (options.counter == null || typeof options.counter !== "number") {
          throw new Error('Expecting options.counter to be a number when options.type is "hotp".');
        }
        params.push(`&counter=${options.counter}`);
      }
      if (options.type === "totp" && options.step) {
        params.push(`&period=${options.step}`);
      }
      if (options.digits) {
        params.push(`&digits=${options.digits}`);
      }
      if (options.algorithm) {
        params.push(`&algorithm=${options.algorithm.toUpperCase()}`);
      }
      if (options.issuer) {
        params.push(`&issuer=${encodeURIComponent(options.issuer)}`);
      }
      return tmpl.replace("{labelPrefix}", encodeURIComponent(options.issuer || options.accountName)).replace("{accountName}", encodeURIComponent(options.accountName)).replace("{secret}", options.secret).replace("{query}", params.join(""));
    }
    class OTP {
      constructor(defaultOptions = {}) {
        this._defaultOptions = Object.freeze({
          ...defaultOptions
        });
        this._options = Object.freeze({});
      }
      create(defaultOptions = {}) {
        return new OTP(defaultOptions);
      }
      clone(defaultOptions = {}) {
        const instance = this.create({
          ...this._defaultOptions,
          ...defaultOptions
        });
        instance.options = this._options;
        return instance;
      }
      get options() {
        return Object.freeze({
          ...this._defaultOptions,
          ...this._options
        });
      }
      set options(options) {
        this._options = Object.freeze({
          ...this._options,
          ...options
        });
      }
      allOptions() {
        return this.options;
      }
      resetOptions() {
        this._options = Object.freeze({});
      }
    }
    function hotpOptionsValidator(options) {
      if (typeof options.createDigest !== "function") {
        throw new Error("Expecting options.createDigest to be a function.");
      }
      if (typeof options.createHmacKey !== "function") {
        throw new Error("Expecting options.createHmacKey to be a function.");
      }
      if (typeof options.digits !== "number") {
        throw new Error("Expecting options.digits to be a number.");
      }
      if (!options.algorithm || HASH_ALGORITHMS.indexOf(options.algorithm) < 0) {
        throw new Error(`Expecting options.algorithm to be one of ${HASH_ALGORITHMS.join(", ")}. Received ${options.algorithm}.`);
      }
      if (!options.encoding || KEY_ENCODINGS.indexOf(options.encoding) < 0) {
        throw new Error(`Expecting options.encoding to be one of ${KEY_ENCODINGS.join(", ")}. Received ${options.encoding}.`);
      }
    }
    const hotpCreateHmacKey = (algorithm, secret, encoding) => {
      return Buffer.from(secret, encoding).toString("hex");
    };
    function hotpDefaultOptions() {
      const options = {
        algorithm: exports$1.HashAlgorithms.SHA1,
        createHmacKey: hotpCreateHmacKey,
        createDigest: createDigestPlaceholder,
        digits: 6,
        encoding: exports$1.KeyEncodings.ASCII
      };
      return options;
    }
    function hotpOptions(opt) {
      const options = {
        ...hotpDefaultOptions(),
        ...opt
      };
      hotpOptionsValidator(options);
      return Object.freeze(options);
    }
    function hotpCounter(counter) {
      const hexCounter = counter.toString(16);
      return padStart(hexCounter, 16, "0");
    }
    function hotpDigestToToken(hexDigest, digits) {
      const digest = Buffer.from(hexDigest, "hex");
      const offset = digest[digest.length - 1] & 15;
      const binary = (digest[offset] & 127) << 24 | (digest[offset + 1] & 255) << 16 | (digest[offset + 2] & 255) << 8 | digest[offset + 3] & 255;
      const token = binary % Math.pow(10, digits);
      return padStart(String(token), digits, "0");
    }
    function hotpDigest(secret, counter, options) {
      const hexCounter = hotpCounter(counter);
      const hmacKey = options.createHmacKey(options.algorithm, secret, options.encoding);
      return options.createDigest(options.algorithm, hmacKey, hexCounter);
    }
    function hotpToken(secret, counter, options) {
      const hexDigest = options.digest || hotpDigest(secret, counter, options);
      return hotpDigestToToken(hexDigest, options.digits);
    }
    function hotpCheck(token, secret, counter, options) {
      if (!isTokenValid(token)) {
        return false;
      }
      const systemToken = hotpToken(secret, counter, options);
      return token === systemToken;
    }
    function hotpKeyuri(accountName, issuer, secret, counter, options) {
      return keyuri({
        algorithm: options.algorithm,
        digits: options.digits,
        type: exports$1.Strategy.HOTP,
        accountName,
        counter,
        issuer,
        secret
      });
    }
    class HOTP extends OTP {
      create(defaultOptions = {}) {
        return new HOTP(defaultOptions);
      }
      allOptions() {
        return hotpOptions(this.options);
      }
      generate(secret, counter) {
        return hotpToken(secret, counter, this.allOptions());
      }
      check(token, secret, counter) {
        return hotpCheck(token, secret, counter, this.allOptions());
      }
      verify(opts) {
        if (typeof opts !== "object") {
          throw new Error("Expecting argument 0 of verify to be an object");
        }
        return this.check(opts.token, opts.secret, opts.counter);
      }
      keyuri(accountName, issuer, secret, counter) {
        return hotpKeyuri(accountName, issuer, secret, counter, this.allOptions());
      }
    }
    function parseWindowBounds(win) {
      if (typeof win === "number") {
        return [Math.abs(win), Math.abs(win)];
      }
      if (Array.isArray(win)) {
        const [past, future] = win;
        if (typeof past === "number" && typeof future === "number") {
          return [Math.abs(past), Math.abs(future)];
        }
      }
      throw new Error("Expecting options.window to be an number or [number, number].");
    }
    function totpOptionsValidator(options) {
      hotpOptionsValidator(options);
      parseWindowBounds(options.window);
      if (typeof options.epoch !== "number") {
        throw new Error("Expecting options.epoch to be a number.");
      }
      if (typeof options.step !== "number") {
        throw new Error("Expecting options.step to be a number.");
      }
    }
    const totpPadSecret = (secret, encoding, minLength) => {
      const currentLength = secret.length;
      const hexSecret = Buffer.from(secret, encoding).toString("hex");
      if (currentLength < minLength) {
        const newSecret = new Array(minLength - currentLength + 1).join(hexSecret);
        return Buffer.from(newSecret, "hex").slice(0, minLength).toString("hex");
      }
      return hexSecret;
    };
    const totpCreateHmacKey = (algorithm, secret, encoding) => {
      switch (algorithm) {
        case exports$1.HashAlgorithms.SHA1:
          return totpPadSecret(secret, encoding, 20);
        case exports$1.HashAlgorithms.SHA256:
          return totpPadSecret(secret, encoding, 32);
        case exports$1.HashAlgorithms.SHA512:
          return totpPadSecret(secret, encoding, 64);
        default:
          throw new Error(`Expecting algorithm to be one of ${HASH_ALGORITHMS.join(", ")}. Received ${algorithm}.`);
      }
    };
    function totpDefaultOptions() {
      const options = {
        algorithm: exports$1.HashAlgorithms.SHA1,
        createDigest: createDigestPlaceholder,
        createHmacKey: totpCreateHmacKey,
        digits: 6,
        encoding: exports$1.KeyEncodings.ASCII,
        epoch: Date.now(),
        step: 30,
        window: 0
      };
      return options;
    }
    function totpOptions(opt) {
      const options = {
        ...totpDefaultOptions(),
        ...opt
      };
      totpOptionsValidator(options);
      return Object.freeze(options);
    }
    function totpCounter(epoch, step) {
      return Math.floor(epoch / step / 1e3);
    }
    function totpToken(secret, options) {
      const counter = totpCounter(options.epoch, options.step);
      return hotpToken(secret, counter, options);
    }
    function totpEpochsInWindow(epoch, direction, deltaPerEpoch, numOfEpoches) {
      const result = [];
      if (numOfEpoches === 0) {
        return result;
      }
      for (let i = 1; i <= numOfEpoches; i++) {
        const delta = direction * i * deltaPerEpoch;
        result.push(epoch + delta);
      }
      return result;
    }
    function totpEpochAvailable(epoch, step, win) {
      const bounds = parseWindowBounds(win);
      const delta = step * 1e3;
      return {
        current: epoch,
        past: totpEpochsInWindow(epoch, -1, delta, bounds[0]),
        future: totpEpochsInWindow(epoch, 1, delta, bounds[1])
      };
    }
    function totpCheck(token, secret, options) {
      if (!isTokenValid(token)) {
        return false;
      }
      const systemToken = totpToken(secret, options);
      return token === systemToken;
    }
    function totpCheckByEpoch(epochs, token, secret, options) {
      let position = null;
      epochs.some((epoch, idx) => {
        if (totpCheck(token, secret, {
          ...options,
          epoch
        })) {
          position = idx + 1;
          return true;
        }
        return false;
      });
      return position;
    }
    function totpCheckWithWindow(token, secret, options) {
      if (totpCheck(token, secret, options)) {
        return 0;
      }
      const epochs = totpEpochAvailable(options.epoch, options.step, options.window);
      const backward = totpCheckByEpoch(epochs.past, token, secret, options);
      if (backward !== null) {
        return backward * -1;
      }
      return totpCheckByEpoch(epochs.future, token, secret, options);
    }
    function totpTimeUsed(epoch, step) {
      return Math.floor(epoch / 1e3) % step;
    }
    function totpTimeRemaining(epoch, step) {
      return step - totpTimeUsed(epoch, step);
    }
    function totpKeyuri(accountName, issuer, secret, options) {
      return keyuri({
        algorithm: options.algorithm,
        digits: options.digits,
        step: options.step,
        type: exports$1.Strategy.TOTP,
        accountName,
        issuer,
        secret
      });
    }
    class TOTP extends HOTP {
      create(defaultOptions = {}) {
        return new TOTP(defaultOptions);
      }
      allOptions() {
        return totpOptions(this.options);
      }
      generate(secret) {
        return totpToken(secret, this.allOptions());
      }
      checkDelta(token, secret) {
        return totpCheckWithWindow(token, secret, this.allOptions());
      }
      check(token, secret) {
        const delta = this.checkDelta(token, secret);
        return typeof delta === "number";
      }
      verify(opts) {
        if (typeof opts !== "object") {
          throw new Error("Expecting argument 0 of verify to be an object");
        }
        return this.check(opts.token, opts.secret);
      }
      timeRemaining() {
        const options = this.allOptions();
        return totpTimeRemaining(options.epoch, options.step);
      }
      timeUsed() {
        const options = this.allOptions();
        return totpTimeUsed(options.epoch, options.step);
      }
      keyuri(accountName, issuer, secret) {
        return totpKeyuri(accountName, issuer, secret, this.allOptions());
      }
    }
    function authenticatorOptionValidator(options) {
      totpOptionsValidator(options);
      if (typeof options.keyDecoder !== "function") {
        throw new Error("Expecting options.keyDecoder to be a function.");
      }
      if (options.keyEncoder && typeof options.keyEncoder !== "function") {
        throw new Error("Expecting options.keyEncoder to be a function.");
      }
    }
    function authenticatorDefaultOptions() {
      const options = {
        algorithm: exports$1.HashAlgorithms.SHA1,
        createDigest: createDigestPlaceholder,
        createHmacKey: totpCreateHmacKey,
        digits: 6,
        encoding: exports$1.KeyEncodings.HEX,
        epoch: Date.now(),
        step: 30,
        window: 0
      };
      return options;
    }
    function authenticatorOptions(opt) {
      const options = {
        ...authenticatorDefaultOptions(),
        ...opt
      };
      authenticatorOptionValidator(options);
      return Object.freeze(options);
    }
    function authenticatorEncoder(secret, options) {
      return options.keyEncoder(secret, options.encoding);
    }
    function authenticatorDecoder(secret, options) {
      return options.keyDecoder(secret, options.encoding);
    }
    function authenticatorGenerateSecret(numberOfBytes, options) {
      const key = options.createRandomBytes(numberOfBytes, options.encoding);
      return authenticatorEncoder(key, options);
    }
    function authenticatorToken(secret, options) {
      return totpToken(authenticatorDecoder(secret, options), options);
    }
    function authenticatorCheckWithWindow(token, secret, options) {
      return totpCheckWithWindow(token, authenticatorDecoder(secret, options), options);
    }
    class Authenticator extends TOTP {
      create(defaultOptions = {}) {
        return new Authenticator(defaultOptions);
      }
      allOptions() {
        return authenticatorOptions(this.options);
      }
      generate(secret) {
        return authenticatorToken(secret, this.allOptions());
      }
      checkDelta(token, secret) {
        return authenticatorCheckWithWindow(token, secret, this.allOptions());
      }
      encode(secret) {
        return authenticatorEncoder(secret, this.allOptions());
      }
      decode(secret) {
        return authenticatorDecoder(secret, this.allOptions());
      }
      generateSecret(numberOfBytes = 10) {
        return authenticatorGenerateSecret(numberOfBytes, this.allOptions());
      }
    }
    exports$1.Authenticator = Authenticator;
    exports$1.HASH_ALGORITHMS = HASH_ALGORITHMS;
    exports$1.HOTP = HOTP;
    exports$1.KEY_ENCODINGS = KEY_ENCODINGS;
    exports$1.OTP = OTP;
    exports$1.STRATEGY = STRATEGY;
    exports$1.TOTP = TOTP;
    exports$1.authenticatorCheckWithWindow = authenticatorCheckWithWindow;
    exports$1.authenticatorDecoder = authenticatorDecoder;
    exports$1.authenticatorDefaultOptions = authenticatorDefaultOptions;
    exports$1.authenticatorEncoder = authenticatorEncoder;
    exports$1.authenticatorGenerateSecret = authenticatorGenerateSecret;
    exports$1.authenticatorOptionValidator = authenticatorOptionValidator;
    exports$1.authenticatorOptions = authenticatorOptions;
    exports$1.authenticatorToken = authenticatorToken;
    exports$1.createDigestPlaceholder = createDigestPlaceholder;
    exports$1.hotpCheck = hotpCheck;
    exports$1.hotpCounter = hotpCounter;
    exports$1.hotpCreateHmacKey = hotpCreateHmacKey;
    exports$1.hotpDefaultOptions = hotpDefaultOptions;
    exports$1.hotpDigestToToken = hotpDigestToToken;
    exports$1.hotpKeyuri = hotpKeyuri;
    exports$1.hotpOptions = hotpOptions;
    exports$1.hotpOptionsValidator = hotpOptionsValidator;
    exports$1.hotpToken = hotpToken;
    exports$1.isTokenValid = isTokenValid;
    exports$1.keyuri = keyuri;
    exports$1.objectValues = objectValues;
    exports$1.padStart = padStart;
    exports$1.totpCheck = totpCheck;
    exports$1.totpCheckByEpoch = totpCheckByEpoch;
    exports$1.totpCheckWithWindow = totpCheckWithWindow;
    exports$1.totpCounter = totpCounter;
    exports$1.totpCreateHmacKey = totpCreateHmacKey;
    exports$1.totpDefaultOptions = totpDefaultOptions;
    exports$1.totpEpochAvailable = totpEpochAvailable;
    exports$1.totpKeyuri = totpKeyuri;
    exports$1.totpOptions = totpOptions;
    exports$1.totpOptionsValidator = totpOptionsValidator;
    exports$1.totpPadSecret = totpPadSecret;
    exports$1.totpTimeRemaining = totpTimeRemaining;
    exports$1.totpTimeUsed = totpTimeUsed;
    exports$1.totpToken = totpToken;
  })(core);
  return core;
}
var hasRequiredPresetDefault;
function requirePresetDefault() {
  if (hasRequiredPresetDefault) return presetDefault;
  hasRequiredPresetDefault = 1;
  Object.defineProperty(presetDefault, "__esModule", { value: true });
  var pluginCrypto2 = requirePluginCrypto();
  var pluginThirtyTwo2 = requirePluginThirtyTwo();
  var core2 = requireCore();
  const hotp = new core2.HOTP({
    createDigest: pluginCrypto2.createDigest
  });
  const totp = new core2.TOTP({
    createDigest: pluginCrypto2.createDigest
  });
  const authenticator = new core2.Authenticator({
    createDigest: pluginCrypto2.createDigest,
    createRandomBytes: pluginCrypto2.createRandomBytes,
    keyDecoder: pluginThirtyTwo2.keyDecoder,
    keyEncoder: pluginThirtyTwo2.keyEncoder
  });
  presetDefault.authenticator = authenticator;
  presetDefault.hotp = hotp;
  presetDefault.totp = totp;
  return presetDefault;
}
var hasRequiredOtplib;
function requireOtplib() {
  if (hasRequiredOtplib) return otplib;
  hasRequiredOtplib = 1;
  (function(exports$1) {
    Object.defineProperty(exports$1, "__esModule", { value: true });
    var presetDefault2 = requirePresetDefault();
    Object.keys(presetDefault2).forEach(function(k) {
      if (k !== "default") Object.defineProperty(exports$1, k, {
        enumerable: true,
        get: function() {
          return presetDefault2[k];
        }
      });
    });
  })(otplib);
  return otplib;
}
var otplibExports = requireOtplib();
async function isBiometricAvailable() {
  if (process.platform === "darwin") {
    try {
      const canPrompt = electron.systemPreferences.canPromptTouchID();
      return canPrompt;
    } catch {
      return false;
    }
  }
  return false;
}
async function promptBiometric(reason) {
  if (process.platform === "darwin") {
    return promptTouchId(reason);
  }
  return { ok: false, reason: "not-available" };
}
async function promptTouchId(reason) {
  try {
    const available = electron.systemPreferences.canPromptTouchID();
    if (!available) {
      return { ok: false, reason: "not-available" };
    }
    await electron.systemPreferences.promptTouchID(`OpenClaw — ${reason}`);
    return { ok: true };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes("cancelled") || msg.includes("userCancel")) {
      return { ok: false, reason: "cancelled" };
    }
    return { ok: false, reason: "failed" };
  }
}
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1e3;
const RECOVERY_CODE_COUNT = 8;
const CLEANUP_INTERVAL_MS = 6e4;
class AuthEngine {
  constructor(store, sessions) {
    this.store = store;
    this.sessions = sessions;
    otplibExports.authenticator.options = {
      window: 1,
      // Accept codes 30s before/after for clock drift
      digits: 6
    };
    this.cleanupInterval = setInterval(() => this.pruneExpired(), CLEANUP_INTERVAL_MS);
  }
  /** Pending TOTP logins: nonce → state */
  pendingLogins = /* @__PURE__ */ new Map();
  /** Login attempt tracker: username (lowercased) → attempt state */
  loginAttempts = /* @__PURE__ */ new Map();
  cleanupInterval;
  /** Stop the cleanup timer (call on shutdown). */
  destroy() {
    clearInterval(this.cleanupInterval);
  }
  /** Remove expired pending logins and stale lockout entries. */
  pruneExpired() {
    const now = Date.now();
    for (const [nonce, pending] of this.pendingLogins) {
      if (now > pending.expiresAt) {
        this.pendingLogins.delete(nonce);
      }
    }
    for (const [key, attempt] of this.loginAttempts) {
      if (attempt.lockedUntil > 0 && attempt.lockedUntil <= now) {
        this.loginAttempts.delete(key);
      }
    }
  }
  // ─── First-Run Setup ─────────────────────────────────────────────────
  /** True if no users exist yet (first launch). */
  isFirstRun() {
    return !this.store.hasUsers();
  }
  /** Create the initial Super Admin account with TOTP + recovery codes. */
  async createInitialUser(params) {
    const profile = await this.store.createUser({
      username: params.username,
      role: "super-admin",
      password: params.password
    });
    const totpSetup = await this.generateTotpSetup(params.username);
    const recoveryCodes = this.generateRecoveryCodesList();
    await this.store.setRecoveryCodes(profile.id, recoveryCodes);
    return { profile, totpSetup, recoveryCodes };
  }
  // ─── Login ──────────────────────────────────────────────────────────
  /**
   * Authenticate with username + password.
   *
   * If TOTP is enabled, returns `requiresTotp: true` with a nonce.
   * The caller must then call `verifyTotp()` to complete login.
   */
  async login(username, password) {
    const lockoutMs = this.lockoutRemaining(username);
    if (lockoutMs > 0) {
      this.store.auditLog({ event: "login_locked", userId: void 0, method: "password", success: false });
      return { ok: false, reason: "account-locked" };
    }
    const user = this.store.getUserByUsername(username);
    if (!user) {
      await sleep$2(200);
      return { ok: false, reason: "invalid-credentials" };
    }
    const valid = await this.store.verifyPassword(user.id, password);
    if (!valid) {
      this.recordLoginFailure(username);
      this.store.auditLog({ event: "login_failed", userId: user.id, method: "password", success: false });
      return { ok: false, reason: "invalid-credentials" };
    }
    this.clearLoginAttempts(username);
    if (user.totp_enabled) {
      const nonce = node_crypto.randomBytes(16).toString("hex");
      this.pendingLogins.set(nonce, {
        userId: user.id,
        role: user.role,
        expiresAt: Date.now() + 5 * 60 * 1e3
        // 5 min to enter TOTP
      });
      return { ok: true, session: {}, token: "", requiresTotp: true, nonce };
    }
    const { session, token } = this.sessions.createSession(user.id, user.role);
    this.store.updateLastLogin(user.id);
    this.store.auditLog({ event: "login_success", userId: user.id, method: "password", success: true });
    return { ok: true, session, token, requiresTotp: false };
  }
  /** Complete login after TOTP verification. */
  async verifyTotp(nonce, code) {
    const pending = this.pendingLogins.get(nonce);
    if (!pending || Date.now() > pending.expiresAt) {
      this.pendingLogins.delete(nonce);
      return { ok: false, reason: "expired" };
    }
    const secret = this.store.getTotpSecret(pending.userId);
    if (!secret) {
      return { ok: false, reason: "invalid-code" };
    }
    const valid = otplibExports.authenticator.verify({ token: code, secret });
    if (!valid) {
      const recoveryUsed = await this.store.useRecoveryCode(pending.userId, code);
      if (!recoveryUsed) {
        this.store.auditLog({ event: "totp_failed", userId: pending.userId, method: "totp", success: false });
        return { ok: false, reason: "invalid-code" };
      }
      this.store.auditLog({ event: "recovery_code_used", userId: pending.userId, method: "recovery", success: true });
    }
    this.pendingLogins.delete(nonce);
    const { session, token } = this.sessions.createSession(pending.userId, pending.role);
    this.store.updateLastLogin(pending.userId);
    this.store.auditLog({ event: "login_success", userId: pending.userId, method: "totp", success: true });
    return { ok: true, session, token };
  }
  // ─── Biometric Login ─────────────────────────────────────────────────
  /**
   * Authenticate via biometric (Touch ID / Windows Hello).
   * Only available if the current user has biometric enrolled.
   */
  async biometricLogin(username) {
    const user = this.store.getUserByUsername(username);
    if (!user || !user.biometric_enrolled) {
      return { ok: false, reason: "invalid-credentials" };
    }
    const result = await promptBiometric("to sign in to OpenClaw Command Center");
    if (!result.ok) {
      this.store.auditLog({ event: "biometric_login_failed", userId: user.id, method: "biometric", success: false });
      return { ok: false, reason: "invalid-credentials" };
    }
    const { session, token } = this.sessions.createSession(user.id, user.role);
    this.store.updateLastLogin(user.id);
    this.store.auditLog({ event: "login_success", userId: user.id, method: "biometric", success: true });
    return { ok: true, session, token, requiresTotp: false };
  }
  // ─── Elevation (Re-Auth for Sensitive Ops) ────────────────────────────
  /**
   * Re-authenticate to elevate a session for sensitive operations.
   * Tries biometric first; falls back to TOTP code if provided.
   */
  async elevate(sessionToken, totpCode) {
    const session = this.sessions.resolve(sessionToken);
    if (!session) {
      return { ok: false, reason: "totp-required" };
    }
    const user = this.store.getUserById(session.userId);
    if (!user) {
      return { ok: false, reason: "totp-required" };
    }
    const biometricAvailable = await isBiometricAvailable();
    if (biometricAvailable && user.biometric_enrolled) {
      const result = await promptBiometric("to confirm this action");
      if (result.ok) {
        this.sessions.elevateSession(sessionToken);
        this.store.auditLog({ event: "elevation_success", userId: user.id, method: "biometric", success: true });
        return { ok: true };
      }
      if (result.reason === "cancelled") {
        return { ok: false, reason: "biometric-cancelled" };
      }
    }
    if (user.totp_enabled && totpCode) {
      const secret = this.store.getTotpSecret(user.id);
      if (secret && otplibExports.authenticator.verify({ token: totpCode, secret })) {
        this.sessions.elevateSession(sessionToken);
        this.store.auditLog({ event: "elevation_success", userId: user.id, method: "totp", success: true });
        return { ok: true };
      }
      this.store.auditLog({ event: "elevation_failed", userId: user.id, method: "totp", success: false });
      return { ok: false, reason: "invalid-code" };
    }
    return { ok: false, reason: "totp-required" };
  }
  // ─── TOTP Setup ──────────────────────────────────────────────────────
  /** Generate a new TOTP secret and QR code for setup. */
  async generateTotpSetup(username) {
    const secret = otplibExports.authenticator.generateSecret(32);
    const otpAuthUrl = otplibExports.authenticator.keyuri(username, "OpenClaw Command Center", secret);
    let qrDataUrl = "";
    try {
      const qrcode = await Promise.resolve().then(() => require("./index-BLk21_Zf.cjs")).then((n) => n.index);
      qrDataUrl = await qrcode.toDataURL(otpAuthUrl, { width: 200 });
    } catch {
    }
    return { secret, otpAuthUrl, qrDataUrl };
  }
  /** Confirm TOTP setup by verifying a code, then save the secret. */
  async confirmTotpSetup(params) {
    const valid = otplibExports.authenticator.verify({ token: params.code, secret: params.secret });
    if (!valid) {
      return false;
    }
    this.store.setTotpSecret(params.userId, params.secret);
    this.store.auditLog({ event: "totp_setup", userId: params.userId, method: "totp", success: true });
    return true;
  }
  // ─── Biometric Enrollment ─────────────────────────────────────────────
  /** Enroll biometric for a user (prompt + store flag). */
  async enrollBiometric(userId) {
    const result = await promptBiometric("to enroll biometric for OpenClaw Command Center");
    if (!result.ok) {
      return false;
    }
    this.store.setBiometricEnrolled(userId, true);
    this.store.auditLog({ event: "biometric_enrolled", userId, method: "biometric", success: true });
    return true;
  }
  // ─── User Management Facade ───────────────────────────────────────────
  /** List all users. */
  listUsers() {
    return this.store.listUsers();
  }
  /** Create a user (admin-initiated). */
  async createUser(params) {
    return this.store.createUser(params);
  }
  /** Update a user's role. */
  updateUserRole(userId, newRole) {
    return this.store.updateUserRole(userId, newRole);
  }
  /** Admin-initiated password reset. Invalidates target's sessions. */
  async resetPassword(userId, newPassword) {
    const result = await this.store.resetPassword(userId, newPassword);
    if (result.ok) {
      this.sessions.invalidateAllForUser(userId);
    }
    return result;
  }
  /** Delete a user. Invalidates target's sessions. */
  deleteUser(userId) {
    const result = this.store.deleteUser(userId);
    if (result.ok) {
      this.sessions.invalidateAllForUser(userId);
    }
    return result;
  }
  /** Self-service password change (verifies current password first). */
  async changePassword(userId, currentPassword, newPassword) {
    const valid = await this.store.verifyPassword(userId, currentPassword);
    if (!valid) {
      return { ok: false, reason: "Current password is incorrect" };
    }
    const result = await this.store.resetPassword(userId, newPassword);
    if (result.ok) {
      this.store.auditLog({ event: "password_changed", userId, method: "self-service", success: true });
    }
    return result;
  }
  /** Get audit log entries. */
  getAuditLog(limit) {
    return this.store.getAuditLog(limit ?? 100);
  }
  // ─── Session ─────────────────────────────────────────────────────────
  getSession(token) {
    return this.sessions.resolve(token);
  }
  logout(token) {
    const session = this.sessions.resolve(token);
    if (session) {
      this.store.auditLog({ event: "logout", userId: session.userId, success: true });
    }
    this.sessions.invalidate(token);
  }
  async biometricAvailable() {
    return isBiometricAvailable();
  }
  // ─── Rate Limiting Helpers ────────────────────────────────────────────
  /** Record a failed login attempt. Returns true if the account is now locked. */
  recordLoginFailure(username) {
    const key = username.toLowerCase();
    const existing = this.loginAttempts.get(key) ?? { failures: 0, lockedUntil: 0 };
    existing.failures++;
    if (existing.failures >= MAX_FAILED_ATTEMPTS) {
      existing.lockedUntil = Date.now() + LOCKOUT_DURATION_MS;
      this.store.auditLog({ event: "account_locked", method: "rate-limit", success: false });
    }
    this.loginAttempts.set(key, existing);
    return existing.failures >= MAX_FAILED_ATTEMPTS;
  }
  /** Clear failed attempt counter on successful login. */
  clearLoginAttempts(username) {
    this.loginAttempts.delete(username.toLowerCase());
  }
  /** Check if an account is currently locked. Returns remaining lockout ms or 0. */
  lockoutRemaining(username) {
    const entry = this.loginAttempts.get(username.toLowerCase());
    if (!entry || entry.lockedUntil <= Date.now()) {
      return 0;
    }
    return entry.lockedUntil - Date.now();
  }
  // ─── Recovery Code Helpers ────────────────────────────────────────────
  /** Generate a list of human-readable recovery codes (XXXX-XXXX format). */
  generateRecoveryCodesList() {
    const codes = [];
    for (let i = 0; i < RECOVERY_CODE_COUNT; i++) {
      const raw = node_crypto.randomBytes(4).toString("hex").toUpperCase();
      codes.push(`${raw.slice(0, 4)}-${raw.slice(4, 8)}`);
    }
    return codes;
  }
}
function sleep$2(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
const ROLE_PERMISSIONS = {
  "viewer": [
    "view:dashboard",
    "view:logs",
    "view:sessions",
    "skills:list"
  ],
  "operator": [
    "view:dashboard",
    "view:logs",
    "view:sessions",
    "env:start",
    "env:stop",
    "skills:list",
    "security:view"
  ],
  "admin": [
    "view:dashboard",
    "view:logs",
    "view:sessions",
    "env:start",
    "env:stop",
    "config:read",
    "config:write",
    "skills:list",
    "skills:install",
    "skills:approve",
    "security:view",
    "security:remediate",
    "backup:create",
    "backup:restore",
    "users:list"
  ],
  "super-admin": [
    "view:dashboard",
    "view:logs",
    "view:sessions",
    "env:start",
    "env:stop",
    "config:read",
    "config:write",
    "skills:list",
    "skills:install",
    "skills:approve",
    "security:view",
    "security:remediate",
    "backup:create",
    "backup:restore",
    "users:list",
    "users:create",
    "users:delete",
    "users:modify-role",
    "users:reset-password"
  ]
};
function hasPermission(role, permission) {
  return ROLE_PERMISSIONS[role]?.includes(permission) ?? false;
}
function registerAuthIpcHandlers(engine, sessions) {
  electron.ipcMain.handle(IPC_CHANNELS.AUTH_LOGIN, async (_event, username, password) => {
    const result = await engine.login(username, password);
    if (!result.ok) {
      return null;
    }
    if (result.requiresTotp) {
      return { requiresTotp: true, nonce: result.nonce };
    }
    return { session: result.session, token: result.token };
  });
  electron.ipcMain.handle(IPC_CHANNELS.AUTH_VERIFY_TOTP, async (_event, nonce, code) => {
    const result = await engine.verifyTotp(nonce, code);
    if (!result.ok) {
      return null;
    }
    return { session: result.session, token: result.token };
  });
  electron.ipcMain.handle(IPC_CHANNELS.AUTH_BIOMETRIC, async (_event, username) => {
    const result = await engine.biometricLogin(username);
    if (!result.ok) {
      return null;
    }
    return { session: result.session, token: result.token };
  });
  electron.ipcMain.handle(IPC_CHANNELS.AUTH_LOGOUT, async (_event, token) => {
    engine.logout(token);
  });
  electron.ipcMain.handle(IPC_CHANNELS.AUTH_SESSION, async (_event, token) => {
    return engine.getSession(token);
  });
  electron.ipcMain.handle(IPC_CHANNELS.AUTH_ELEVATE, async (_event, token, totpCode) => {
    const result = await engine.elevate(token, totpCode);
    return result;
  });
  electron.ipcMain.handle(IPC_CHANNELS.AUTH_IS_FIRST_RUN, async () => {
    return engine.isFirstRun();
  });
  electron.ipcMain.handle(IPC_CHANNELS.AUTH_CREATE_INITIAL_USER, async (_event, username, password) => {
    if (!engine.isFirstRun()) {
      throw new Error("Initial user already created");
    }
    return engine.createInitialUser({ username, password });
  });
  electron.ipcMain.handle(IPC_CHANNELS.AUTH_CONFIRM_TOTP, async (_event, token, secret, code) => {
    const session = engine.getSession(token);
    if (!session) {
      throw new Error("Unauthorized");
    }
    return engine.confirmTotpSetup({ userId: session.userId, secret, code });
  });
  electron.ipcMain.handle(IPC_CHANNELS.AUTH_BIOMETRIC_AVAILABLE, async () => {
    return engine.biometricAvailable();
  });
  electron.ipcMain.handle(IPC_CHANNELS.AUTH_ENROLL_BIOMETRIC, async (_event, token) => {
    const session = engine.getSession(token);
    if (!session) {
      throw new Error("Unauthorized");
    }
    return engine.enrollBiometric(session.userId);
  });
  electron.ipcMain.handle(IPC_CHANNELS.AUTH_LIST_USERS, async (_event, token) => {
    const session = engine.getSession(token);
    if (!session || !hasPermission(session.role, "users:list")) {
      throw new Error("Unauthorized");
    }
    return engine.listUsers();
  });
  electron.ipcMain.handle(IPC_CHANNELS.AUTH_CREATE_USER, async (_event, token, params) => {
    const session = engine.getSession(token);
    if (!session || !hasPermission(session.role, "users:create")) {
      throw new Error("Unauthorized");
    }
    if (!session.elevated) {
      throw new Error("Elevation required to create users");
    }
    const created = await engine.createUser({
      username: params.username,
      role: params.role,
      password: params.password
    });
    sessions.dropElevation(token);
    return created;
  });
  electron.ipcMain.handle(IPC_CHANNELS.AUTH_UPDATE_ROLE, async (_event, token, userId, newRole) => {
    const session = engine.getSession(token);
    if (!session || !hasPermission(session.role, "users:modify-role")) {
      throw new Error("Unauthorized");
    }
    if (!session.elevated) {
      throw new Error("Elevation required to modify user roles");
    }
    if (userId === session.userId && newRole !== session.role) {
      throw new Error("Cannot change your own role");
    }
    const result = engine.updateUserRole(userId, newRole);
    sessions.dropElevation(token);
    return result;
  });
  electron.ipcMain.handle(IPC_CHANNELS.AUTH_RESET_PASSWORD, async (_event, token, userId, newPassword) => {
    const session = engine.getSession(token);
    if (!session || !hasPermission(session.role, "users:reset-password")) {
      throw new Error("Unauthorized");
    }
    if (!session.elevated) {
      throw new Error("Elevation required to reset passwords");
    }
    const result = await engine.resetPassword(userId, newPassword);
    sessions.dropElevation(token);
    return result;
  });
  electron.ipcMain.handle(IPC_CHANNELS.AUTH_DELETE_USER, async (_event, token, userId) => {
    const session = engine.getSession(token);
    if (!session || !hasPermission(session.role, "users:delete")) {
      throw new Error("Unauthorized");
    }
    if (!session.elevated) {
      throw new Error("Elevation required to delete users");
    }
    if (userId === session.userId) {
      throw new Error("Cannot delete your own account");
    }
    const result = engine.deleteUser(userId);
    sessions.dropElevation(token);
    return result;
  });
  electron.ipcMain.handle(IPC_CHANNELS.AUTH_AUDIT_LOG, async (_event, token, limit) => {
    const session = engine.getSession(token);
    if (!session || !hasPermission(session.role, "users:list")) {
      throw new Error("Unauthorized");
    }
    return engine.getAuditLog(limit);
  });
  electron.ipcMain.handle(IPC_CHANNELS.AUTH_CHANGE_PASSWORD, async (_event, token, currentPassword, newPassword) => {
    const session = engine.getSession(token);
    if (!session) {
      throw new Error("Unauthorized");
    }
    return engine.changePassword(session.userId, currentPassword, newPassword);
  });
}
const execAsync$2 = node_util.promisify(node_child_process.exec);
const MIN_RAM_GB = 4;
const REC_RAM_GB = 8;
const MIN_DISK_GB = 10;
class SystemValidator {
  detector = new EngineDetector();
  async validate() {
    const checks = await Promise.all([
      this.checkOS(),
      this.checkNode(),
      this.checkDocker(),
      this.checkRAM(),
      this.checkDisk(),
      this.checkPort(DEFAULT_GATEWAY_PORT, "Gateway port"),
      this.checkPort(DEFAULT_BRIDGE_PORT, "Bridge port")
    ]);
    const allPassed = checks.every((c) => c.result === "pass");
    const canProceed = checks.every((c) => c.result !== "fail");
    return { checks, allPassed, canProceed };
  }
  // ─── Individual Checks ──────────────────────────────────────────────
  async checkOS() {
    const platform = process.platform;
    const release = os.release();
    const supported = {
      darwin: { min: 22, label: "macOS 13+" },
      // Ventura = Darwin 22
      win32: { min: 10, label: "Windows 10+" },
      linux: { min: 0, label: "Linux" }
    };
    const entry = supported[platform];
    if (!entry) {
      return {
        name: "Operating System",
        description: "Supported OS required",
        result: "fail",
        message: `${platform} is not supported. Use macOS, Windows, or Linux.`,
        autoFixAvailable: false
      };
    }
    const majorVersion = parseInt(release.split(".")[0] ?? "0", 10);
    const pass = majorVersion >= entry.min;
    const osLabel = platform === "darwin" ? `macOS (Darwin ${release})` : platform === "win32" ? `Windows (${release})` : `Linux (${release})`;
    return {
      name: "Operating System",
      description: `${entry.label} required`,
      result: pass ? "pass" : "warn",
      message: pass ? `${osLabel} ✓` : `${osLabel} — consider upgrading`,
      autoFixAvailable: false
    };
  }
  async checkNode() {
    const version = process.versions.node;
    const [major] = version.split(".").map(Number);
    const pass = major >= 22;
    return {
      name: "Node.js Runtime",
      description: "Node.js 22.12.0 or later required",
      result: pass ? "pass" : "fail",
      message: pass ? `Node.js v${version} ✓` : `Node.js v${version} — upgrade to v22.12.0+`,
      autoFixAvailable: false
    };
  }
  async checkDocker() {
    const info = await this.detector.detect();
    const options = this.detector.getInstallOptions();
    if (!info.running) {
      const canFix = options.dockerDesktop || options.dockerCE;
      return {
        name: "Container Engine",
        description: "Docker Desktop or Docker CE required",
        result: "fail",
        message: info.variant === "none" ? "No container engine found. Install Docker Desktop or Docker CE." : `Docker found but not running (${info.variant}).`,
        autoFixAvailable: canFix
      };
    }
    const label = info.variant === "docker-desktop" ? "Docker Desktop" : info.variant === "docker-ce" ? "Docker CE" : info.variant;
    return {
      name: "Container Engine",
      description: "Docker Desktop or Docker CE",
      result: "pass",
      message: `${label} v${info.version} ✓`,
      autoFixAvailable: false
    };
  }
  async checkRAM() {
    const totalGB = os.totalmem() / 1024 / 1024 / 1024;
    const freeGB = os.freemem() / 1024 / 1024 / 1024;
    const totalRounded = Math.round(totalGB * 10) / 10;
    const freeRounded = Math.round(freeGB * 10) / 10;
    let result;
    let message;
    if (freeGB >= MIN_RAM_GB) {
      result = freeGB >= REC_RAM_GB ? "pass" : "warn";
      message = result === "pass" ? `${freeRounded} GB free (${totalRounded} GB total) ✓` : `${freeRounded} GB free — ${REC_RAM_GB} GB recommended for best performance`;
    } else {
      result = "warn";
      message = `Only ${freeRounded} GB free. Close other apps for better performance.`;
    }
    return {
      name: "Available Memory",
      description: `${MIN_RAM_GB} GB free RAM recommended`,
      result,
      message,
      autoFixAvailable: false
    };
  }
  async checkDisk() {
    let freeGB = 0;
    try {
      if (process.platform === "win32") {
        const { stdout } = await execAsync$2(
          'powershell -command "Get-PSDrive C | Select-Object Free | ConvertTo-Json"'
        );
        const data = JSON.parse(stdout);
        freeGB = (data.Free ?? 0) / 1024 / 1024 / 1024;
      } else {
        const { stdout } = await execAsync$2("df -k $HOME");
        const lines = stdout.trim().split("\n");
        const parts = lines[lines.length - 1]?.split(/\s+/) ?? [];
        const availKB = parseInt(parts[3] ?? "0", 10);
        freeGB = availKB / 1024 / 1024;
      }
    } catch {
      return {
        name: "Disk Space",
        description: `${MIN_DISK_GB} GB free space required`,
        result: "warn",
        message: "Could not determine free disk space.",
        autoFixAvailable: false
      };
    }
    const freeRounded = Math.round(freeGB * 10) / 10;
    const pass = freeGB >= MIN_DISK_GB;
    return {
      name: "Disk Space",
      description: `${MIN_DISK_GB} GB free space required`,
      result: pass ? "pass" : "warn",
      message: pass ? `${freeRounded} GB free ✓` : `Only ${freeRounded} GB free — clear space for reliable operation`,
      autoFixAvailable: false
    };
  }
  async checkPort(port, label) {
    const available = await this.isPortAvailable(port);
    return {
      name: `${label} (${port})`,
      description: `Port ${port} must be available`,
      result: available ? "pass" : "warn",
      message: available ? `Port ${port} is available ✓` : `Port ${port} is in use. Another service may conflict.`,
      autoFixAvailable: false
    };
  }
  isPortAvailable(port) {
    return new Promise((resolve) => {
      const server = node_net.createServer();
      server.once("error", () => resolve(false));
      server.once("listening", () => {
        server.close(() => resolve(true));
      });
      server.listen(port, "127.0.0.1");
    });
  }
}
const execAsync$1 = node_util.promisify(node_child_process.exec);
const DOCKER_DESKTOP_URLS = {
  darwin: "https://www.docker.com/products/docker-desktop/",
  win32: "https://www.docker.com/products/docker-desktop/",
  linux: "https://www.docker.com/products/docker-desktop/"
};
const DOCKER_CE_INSTALL_CMD = "curl -fsSL https://get.docker.com | sh && sudo usermod -aG docker $USER";
class DockerInstaller {
  detector = new EngineDetector();
  /**
   * Get available installation options for the current platform.
   */
  getOptions() {
    return this.detector.getInstallOptions();
  }
  /**
   * Open Docker Desktop download page in the system browser.
   * Returns immediately — the user installs manually.
   */
  async openDockerDesktopDownload() {
    const url = DOCKER_DESKTOP_URLS[process.platform] ?? DOCKER_DESKTOP_URLS.darwin;
    await electron.shell.openExternal(url);
  }
  /**
   * For Linux only: build the Docker CE install command to show the user.
   * Does NOT execute it — returns the command for user review in the UI.
   */
  getDockerCEInstallCommand() {
    return DOCKER_CE_INSTALL_CMD;
  }
  /**
   * Poll until Docker becomes available or timeout expires.
   *
   * @param timeoutMs - Max wait time in ms (default 5 minutes)
   * @param onProgress - Called with status as polling progresses
   */
  async waitForDocker(timeoutMs = 5 * 60 * 1e3, onProgress) {
    const deadline = Date.now() + timeoutMs;
    let attempt = 0;
    while (Date.now() < deadline) {
      attempt++;
      onProgress?.(`Checking for Docker… (attempt ${attempt})`);
      const info = await this.detector.detect();
      if (info.running) {
        onProgress?.("Docker is running! ✓");
        return true;
      }
      await sleep$1(5e3);
    }
    onProgress?.("Timed out waiting for Docker.");
    return false;
  }
  /**
   * Verify Docker is reachable after install.
   */
  async verify() {
    try {
      const info = await this.detector.detect();
      if (info.running) {
        return { ok: true, version: info.version };
      }
      return { ok: false, error: "Docker daemon is not running. Try restarting Docker." };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : "Unknown error" };
    }
  }
  /**
   * Start Docker Desktop programmatically (macOS / Windows only).
   */
  async startDockerDesktop() {
    try {
      if (process.platform === "darwin") {
        await execAsync$1("open -a Docker");
        return true;
      }
      if (process.platform === "win32") {
        await execAsync$1('"C:\\Program Files\\Docker\\Docker\\Docker Desktop.exe"');
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }
}
function sleep$1(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
const execAsync = node_util.promisify(node_child_process.exec);
class VoiceGuide {
  enabled = true;
  speaking = false;
  queue = [];
  /** Enable or disable narration. */
  setEnabled(enabled) {
    this.enabled = enabled;
  }
  isEnabled() {
    return this.enabled;
  }
  /**
   * Speak a message. Non-blocking — queues if already speaking.
   */
  async speak(text) {
    if (!this.enabled) {
      return;
    }
    this.queue.push(text);
    if (!this.speaking) {
      await this.processQueue();
    }
  }
  async processQueue() {
    this.speaking = true;
    while (this.queue.length > 0) {
      const text = this.queue.shift();
      await this.sayText(text);
    }
    this.speaking = false;
  }
  async sayText(text) {
    try {
      if (process.platform === "darwin") {
        await execAsync(`say ${JSON.stringify(text)}`);
        return;
      }
      if (process.platform === "linux") {
        await execAsync(`espeak ${JSON.stringify(text)} 2>/dev/null || spd-say ${JSON.stringify(text)}`);
        return;
      }
      if (process.platform === "win32") {
        const script = `Add-Type -AssemblyName System.Speech; $s = New-Object System.Speech.Synthesis.SpeechSynthesizer; $s.Speak(${JSON.stringify(text)})`;
        await execAsync(`powershell -command "${script}"`);
        return;
      }
    } catch {
    }
  }
  /** Stop current speech and clear queue. */
  stop() {
    this.queue = [];
    if (process.platform === "darwin") {
      node_child_process.exec("killall say 2>/dev/null");
    }
  }
}
class GitHubBackupSetup {
  static API_BASE = "https://api.github.com";
  /**
   * Validate a PAT and return the authenticated user info.
   */
  async validatePAT(pat) {
    try {
      const res = await fetch(`${GitHubBackupSetup.API_BASE}/user`, {
        headers: this.headers(pat)
      });
      if (res.status === 401) {
        return { ok: false, reason: "Invalid token. Ensure the PAT is valid." };
      }
      if (!res.ok) {
        return { ok: false, reason: `GitHub API error: ${res.status}` };
      }
      const user = await res.json();
      return { ok: true, user: { login: user.login, name: user.name ?? user.login } };
    } catch (err) {
      return {
        ok: false,
        reason: err instanceof Error ? err.message : "Network error connecting to GitHub"
      };
    }
  }
  /**
   * Create the backup repository for the authenticated user.
   * Returns the created repo info.
   */
  async createBackupRepo(pat) {
    const repoName = `openclaw-backup-${this.machineHash()}`;
    try {
      const checkRes = await fetch(
        `${GitHubBackupSetup.API_BASE}/user/repos?type=private&per_page=100`,
        { headers: this.headers(pat) }
      );
      if (checkRes.ok) {
        const repos = await checkRes.json();
        const existing = repos.find((r) => r.name === repoName);
        if (existing) {
          return {
            ok: true,
            repo: {
              fullName: existing.full_name,
              cloneUrl: existing.clone_url,
              htmlUrl: existing.html_url
            }
          };
        }
      }
      const res = await fetch(`${GitHubBackupSetup.API_BASE}/user/repos`, {
        method: "POST",
        headers: this.headers(pat),
        body: JSON.stringify({
          name: repoName,
          description: "OpenClaw Command Center — automated configuration backups",
          private: true,
          auto_init: true
        })
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        return { ok: false, reason: body.message ?? `GitHub API error: ${res.status}` };
      }
      const repo = await res.json();
      return {
        ok: true,
        repo: {
          fullName: repo.full_name,
          cloneUrl: repo.clone_url,
          htmlUrl: repo.html_url
        }
      };
    } catch (err) {
      return {
        ok: false,
        reason: err instanceof Error ? err.message : "Failed to create backup repository"
      };
    }
  }
  /** Check if a PAT has the `repo` scope. */
  async checkRepoScope(pat) {
    try {
      const res = await fetch(`${GitHubBackupSetup.API_BASE}/user`, {
        headers: this.headers(pat)
      });
      const scopes = res.headers.get("x-oauth-scopes") ?? "";
      return scopes.split(",").map((s) => s.trim()).some((s) => s === "repo" || s === "public_repo");
    } catch {
      return false;
    }
  }
  headers(pat) {
    return {
      Authorization: `Bearer ${pat}`,
      Accept: "application/vnd.github.v3+json",
      "User-Agent": "OpenClaw-Command-Center/0.1.0",
      "Content-Type": "application/json"
    };
  }
  machineHash() {
    const raw = `${os.hostname()}:${os.userInfo().username}:${os.homedir()}`;
    return node_crypto.createHmac("sha256", "occc-backup-key").update(raw).digest("hex").slice(0, 8);
  }
}
class InstallerEngine {
  constructor(docker, containers) {
    this.docker = docker;
    this.containers = containers;
  }
  /**
   * Execute the full installation with progress callbacks.
   */
  async install(config, onProgress) {
    const configDir = path.join(electron.app.getPath("userData"), "openclaw-config");
    const workspaceDir = path.join(electron.app.getPath("userData"), "openclaw-workspace");
    try {
      onProgress({ stage: "preparing", percent: 5, message: "Preparing configuration directories…" });
      await promises.mkdir(configDir, { recursive: true });
      await promises.mkdir(workspaceDir, { recursive: true });
      onProgress({ stage: "pulling-image", percent: 15, message: "Checking OpenClaw image…" });
      const hasImage = await this.docker.imageExists(OPENCLAW_IMAGE);
      if (!hasImage) {
        onProgress({ stage: "pulling-image", percent: 20, message: "Pulling OpenClaw image (this may take a few minutes)…" });
        try {
          const stream = await this.docker.pullImage(OPENCLAW_IMAGE);
          await this.streamToCompletion(stream);
        } catch {
          onProgress({ stage: "pulling-image", percent: 25, message: "Building OpenClaw image from source…" });
          const projectRoot = path.join(electron.app.getAppPath(), "..", "..", "..");
          const stream = await this.docker.buildImage(projectRoot, { t: OPENCLAW_IMAGE });
          await this.streamToCompletion(stream);
        }
      }
      onProgress({ stage: "pulling-image", percent: 40, message: "Image ready ✓" });
      onProgress({ stage: "creating-network", percent: 50, message: "Creating isolated network…" });
      try {
        await this.docker.createNetwork("openclaw-net");
      } catch {
      }
      onProgress({ stage: "creating-volumes", percent: 60, message: "Creating persistent storage…" });
      try {
        await this.docker.createVolume("openclaw-home");
      } catch {
      }
      onProgress({ stage: "creating-container", percent: 70, message: "Configuring OpenClaw container…" });
      const gatewayToken = node_crypto.randomBytes(32).toString("hex");
      await this.containers.createEnvironment({
        configDir,
        workspaceDir,
        gatewayToken,
        gatewayPort: config.gatewayPort ?? DEFAULT_GATEWAY_PORT,
        bridgePort: config.bridgePort ?? DEFAULT_BRIDGE_PORT
      });
      onProgress({ stage: "starting", percent: 85, message: "Starting OpenClaw environment…" });
      await this.containers.startEnvironment();
      onProgress({ stage: "health-check", percent: 92, message: "Waiting for services to become ready…" });
      await this.waitForHealth(15e3);
      onProgress({ stage: "done", percent: 100, message: "OpenClaw is installed and running ✓" });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown error";
      onProgress({ stage: "error", percent: 0, message, error: message });
      throw err;
    }
  }
  async waitForHealth(timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const status = await this.containers.getEnvironmentStatus();
      if (status.health === "healthy") {
        return;
      }
      await sleep(1e3);
    }
  }
  streamToCompletion(stream) {
    return new Promise((resolve, reject) => {
      stream.on("end", resolve);
      stream.on("error", reject);
      stream.resume();
    });
  }
}
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
function registerInstallerIpcHandlers(docker, containers) {
  const validator = new SystemValidator();
  const dockerInstaller = new DockerInstaller();
  const voice = new VoiceGuide();
  const githubSetup = new GitHubBackupSetup();
  const engine = new InstallerEngine(docker, containers);
  electron.ipcMain.handle("occc:install:validate-system", async () => {
    return validator.validate();
  });
  electron.ipcMain.handle("occc:install:docker-options", () => {
    return dockerInstaller.getOptions();
  });
  electron.ipcMain.handle("occc:install:open-docker-download", async () => {
    await dockerInstaller.openDockerDesktopDownload();
  });
  electron.ipcMain.handle("occc:install:docker-ce-command", () => {
    return dockerInstaller.getDockerCEInstallCommand();
  });
  electron.ipcMain.handle("occc:install:start-docker-desktop", async () => {
    return dockerInstaller.startDockerDesktop();
  });
  electron.ipcMain.handle("occc:install:verify-docker", async () => {
    return dockerInstaller.verify();
  });
  electron.ipcMain.handle("occc:install:voice-speak", async (_event, text) => {
    await voice.speak(text);
  });
  electron.ipcMain.handle("occc:install:voice-set-enabled", (_event, enabled) => {
    voice.setEnabled(enabled);
    return enabled;
  });
  electron.ipcMain.handle("occc:install:voice-stop", () => {
    voice.stop();
  });
  electron.ipcMain.handle("occc:install:github-validate-pat", async (_event, pat) => {
    return githubSetup.validatePAT(pat);
  });
  electron.ipcMain.handle("occc:install:github-check-scope", async (_event, pat) => {
    return githubSetup.checkRepoScope(pat);
  });
  electron.ipcMain.handle("occc:install:github-create-repo", async (_event, pat) => {
    return githubSetup.createBackupRepo(pat);
  });
  electron.ipcMain.handle("occc:install:run", async (event, config) => {
    await engine.install(config, (progress) => {
      event.sender.send("occc:install:progress", progress);
    });
  });
}
const CONFIG_FILENAME = "openclaw.json";
class ConfigStore {
  configDir;
  constructor(configDir) {
    this.configDir = configDir ?? path.join(electron.app.getPath("userData"), "openclaw-config");
  }
  /** Read the current config file into a parsed object. */
  async read() {
    const configPath = path.join(this.configDir, CONFIG_FILENAME);
    let raw;
    try {
      raw = await promises.readFile(configPath, "utf-8");
    } catch (err) {
      if (err instanceof Error && err.code === "ENOENT") {
        raw = "{}";
      } else {
        throw new Error(`Cannot read config: ${err instanceof Error ? err.message : String(err)}`, { cause: err });
      }
    }
    let config;
    try {
      config = JSON.parse(raw);
    } catch {
      throw new Error("Config file contains invalid JSON. Edit manually to fix.");
    }
    const checksum = node_crypto.createHash("sha256").update(raw).digest("hex").slice(0, 16);
    return { config, raw, checksum, configPath };
  }
  /**
   * Write the config file atomically.
   *
   * @param config - Parsed config object to write
   * @param expectedChecksum - If provided, fails if the file has changed since last read (optimistic lock)
   */
  async write(config, expectedChecksum) {
    const configPath = path.join(this.configDir, CONFIG_FILENAME);
    const tmpPath = `${configPath}.tmp`;
    if (expectedChecksum) {
      try {
        const current = await this.read();
        if (current.checksum !== expectedChecksum) {
          return {
            ok: false,
            error: "Config was modified by another process. Refresh and try again.",
            checksum: current.checksum
          };
        }
      } catch {
      }
    }
    try {
      await promises.mkdir(this.configDir, { recursive: true });
      const json = JSON.stringify(config, null, 2) + "\n";
      await promises.writeFile(tmpPath, json, { encoding: "utf-8", flush: true });
      await promises.rename(tmpPath, configPath);
      const checksum = node_crypto.createHash("sha256").update(json).digest("hex").slice(0, 16);
      return { ok: true, checksum };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err), checksum: "" };
    }
  }
  /**
   * Deep merge a partial config onto the existing config and write.
   * Only keys present in `patch` are updated.
   */
  async patch(patch, expectedChecksum) {
    const { config } = await this.read();
    const merged = deepMerge(config, patch);
    return this.write(merged, expectedChecksum);
  }
  /** Get the resolved path to the config file (for display). */
  getConfigPath() {
    return path.join(this.configDir, CONFIG_FILENAME);
  }
}
function deepMerge(target, source) {
  const result = { ...target };
  for (const [key, value] of Object.entries(source)) {
    if (value !== null && typeof value === "object" && !Array.isArray(value) && typeof result[key] === "object" && result[key] !== null && !Array.isArray(result[key])) {
      result[key] = deepMerge(
        result[key],
        value
      );
    } else {
      result[key] = value;
    }
  }
  return result;
}
function registerConfigIpcHandlers(sessions) {
  const store = new ConfigStore();
  electron.ipcMain.handle("occc:config:read", async (_event, token) => {
    const session = sessions.resolve(token);
    if (!session || !hasPermission(session.role, "config:read")) {
      throw new Error("Unauthorized");
    }
    return store.read();
  });
  electron.ipcMain.handle("occc:config:path", async (_event, token) => {
    const session = sessions.resolve(token);
    if (!session) {
      throw new Error("Unauthorized");
    }
    return store.getConfigPath();
  });
  electron.ipcMain.handle(
    "occc:config:write",
    async (_event, token, config, expectedChecksum) => {
      const session = sessions.resolve(token);
      if (!session || !hasPermission(session.role, "config:write")) {
        throw new Error("Unauthorized");
      }
      if (!session.elevated) {
        throw new Error("Elevation required to write configuration");
      }
      return store.write(config, expectedChecksum);
    }
  );
  electron.ipcMain.handle(
    "occc:config:patch",
    async (_event, token, patch, expectedChecksum) => {
      const session = sessions.resolve(token);
      if (!session || !hasPermission(session.role, "config:write")) {
        throw new Error("Unauthorized");
      }
      if (!session.elevated) {
        throw new Error("Elevation required to write configuration");
      }
      return store.patch(patch, expectedChecksum);
    }
  );
  electron.ipcMain.handle(
    "occc:config:validate",
    async (_event, token, config) => {
      const session = sessions.resolve(token);
      if (!session || !hasPermission(session.role, "config:read")) {
        throw new Error("Unauthorized");
      }
      try {
        const schemaPath = new URL("../../../../../../src/config/zod-schema.js", typeof document === "undefined" ? require("url").pathToFileURL(__filename).href : _documentCurrentScript && _documentCurrentScript.tagName.toUpperCase() === "SCRIPT" && _documentCurrentScript.src || new URL("index.js", document.baseURI).href);
        const { OpenClawSchema } = await import(schemaPath.pathname);
        const result = OpenClawSchema.safeParse(config);
        if (result.success) {
          return { valid: true, errors: [] };
        }
        const errors = result.error.issues.map((issue) => ({
          path: issue.path.join("."),
          message: issue.message
        }));
        return { valid: false, errors };
      } catch {
        return { valid: true, errors: [], note: "Schema validation unavailable in this environment" };
      }
    }
  );
}
const gotLock = electron.app.requestSingleInstanceLock();
if (!gotLock) {
  console.error(`[${APP_NAME}] Another instance is already running.`);
  electron.app.quit();
}
electron.app.setName(APP_NAME);
if (process.platform === "darwin") {
  electron.app.dock?.setMenu(null);
}
electron.app.on("web-contents-created", (_event, contents) => {
  contents.on("will-navigate", (event) => {
    event.preventDefault();
  });
  contents.setWindowOpenHandler(() => ({ action: "deny" }));
});
let windowManager;
let trayManager;
let dockerClient;
let containerManager;
let authStore;
let sessionManager;
let authEngine;
void electron.app.whenReady().then(async () => {
  console.log(`[${APP_NAME}] Starting (pid: ${process.pid})`);
  const detector = new EngineDetector();
  const engineInfo = await detector.detect();
  console.log(
    `[${APP_NAME}] Docker: ${engineInfo.variant} v${engineInfo.version} (running: ${engineInfo.running})`
  );
  authStore = new AuthStore();
  await authStore.init();
  sessionManager = new SessionManager();
  authEngine = new AuthEngine(authStore, sessionManager);
  console.log(`[${APP_NAME}] Auth: first-run=${authEngine.isFirstRun()}`);
  dockerClient = new DockerEngineClient();
  containerManager = new ContainerManager(dockerClient);
  registerIpcHandlers({ dockerClient, containerManager, sessionManager });
  registerAuthIpcHandlers(authEngine, sessionManager);
  registerInstallerIpcHandlers(dockerClient, containerManager);
  registerConfigIpcHandlers(sessionManager);
  windowManager = new WindowManager();
  await windowManager.createMainWindow();
  trayManager = new TrayManager(windowManager);
  trayManager.create();
  console.log(`[${APP_NAME}] Ready.`);
});
electron.app.on("activate", () => {
  if (electron.BrowserWindow.getAllWindows().length === 0) {
    void windowManager?.createMainWindow();
  }
});
electron.app.on("window-all-closed", () => {
  if (process.platform !== "darwin") ;
});
electron.app.on("before-quit", async () => {
  console.log(`[${APP_NAME}] Shutting down...`);
  sessionManager?.destroy();
  trayManager?.destroy();
});
electron.app.on("second-instance", () => {
  windowManager?.focusMainWindow();
});
