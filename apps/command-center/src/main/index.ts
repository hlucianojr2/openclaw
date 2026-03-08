/**
 * OpenClaw Command Center — Electron Main Process Entry Point.
 *
 * Security hardening:
 *   - contextIsolation: true
 *   - nodeIntegration: false
 *   - sandbox: true
 *   - Strict CSP policy
 *   - IPC via typed preload bridge only
 */

import { app, BrowserWindow } from "electron";
import { WindowManager } from "./window-manager.js";
import { TrayManager } from "./tray-manager.js";
import { registerIpcHandlers } from "./ipc-handlers.js";
import { DockerEngineClient } from "./docker/engine-client.js";
import { ContainerManager } from "./docker/container-manager.js";
import { EngineDetector } from "./docker/engine-detector.js";
import { AuthStore } from "./auth/auth-store.js";
import { SessionManager } from "./auth/session-manager.js";
import { AuthEngine } from "./auth/auth-engine.js";
import { registerAuthIpcHandlers } from "./auth/auth-ipc.js";
import { registerInstallerIpcHandlers } from "./installer/installer-ipc.js";
import { registerConfigIpcHandlers } from "./config/config-ipc.js";
import { McpBridgeServer, McpPolicyStore, McpAuditLogger, registerMcpIpcHandlers } from "./mcp/index.js";
import { APP_NAME, DEFAULT_MCP_BRIDGE_PORT } from "../shared/constants.js";
import { randomBytes } from "node:crypto";

// ─── Single Instance Lock ───────────────────────────────────────────────────

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  console.error(`[${APP_NAME}] Another instance is already running.`);
  app.quit();
}

// ─── App Setup ──────────────────────────────────────────────────────────────

app.setName(APP_NAME);
if (process.platform === "darwin") {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (app.dock as any)?.setMenu(null);
}

// Security: disable navigation to external URLs
app.on("web-contents-created", (_event, contents) => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (contents).on("will-navigate", (event: { preventDefault(): void }) => {
    event.preventDefault();
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (contents).setWindowOpenHandler(() => ({ action: "deny" as const }));
});

// ─── Services ───────────────────────────────────────────────────────────────

let windowManager: WindowManager;
let trayManager: TrayManager;
let dockerClient: DockerEngineClient;
let containerManager: ContainerManager;
let authStore: AuthStore;
let sessionManager: SessionManager;
let authEngine: AuthEngine;
let mcpServer: McpBridgeServer;

// ─── App Lifecycle ──────────────────────────────────────────────────────────

void app.whenReady().then(async () => {
  console.log(`[${APP_NAME}] Starting (pid: ${process.pid})`);

  // Detect Docker engine
  const detector = new EngineDetector();
  const engineInfo = await detector.detect();
  console.log(
    `[${APP_NAME}] Docker: ${engineInfo.variant} v${engineInfo.version} (running: ${engineInfo.running})`,
  );

  // Initialize auth services (must come before window creation)
  authStore = new AuthStore();
  await authStore.init();
  sessionManager = new SessionManager();
  authEngine = new AuthEngine(authStore, sessionManager);
  console.log(`[${APP_NAME}] Auth: first-run=${authEngine.isFirstRun()}`);

  // Initialize Docker client
  dockerClient = new DockerEngineClient();
  containerManager = new ContainerManager(dockerClient);

  // Initialize MCP Bridge
  const mcpPolicyStore = new McpPolicyStore();
  const mcpAuditLogger = new McpAuditLogger();
  // Generate an ephemeral bearer token for the lifetime of this process.
  // The token is stored in memory only and rotates on each app restart.
  const mcpBearerToken = randomBytes(32).toString("hex");
  mcpServer = new McpBridgeServer(mcpPolicyStore, mcpAuditLogger, mcpBearerToken, DEFAULT_MCP_BRIDGE_PORT);
  try {
    await mcpServer.start();
    console.log(`[${APP_NAME}] MCP Bridge: listening on 127.0.0.1:${DEFAULT_MCP_BRIDGE_PORT}`);
  } catch (err: unknown) {
    console.error(`[${APP_NAME}] MCP Bridge: failed to start — ${err instanceof Error ? err.message : String(err)}`);
  }

  // Register IPC handlers (main process ↔ renderer bridge)
  registerIpcHandlers({ dockerClient, containerManager, sessionManager });
  registerAuthIpcHandlers(authEngine, sessionManager);
  registerInstallerIpcHandlers(dockerClient, containerManager, authEngine);
  registerConfigIpcHandlers(sessionManager);
  registerMcpIpcHandlers(mcpServer, mcpPolicyStore, mcpAuditLogger, sessionManager);

  // Create main window
  windowManager = new WindowManager();
  await windowManager.createMainWindow();

  // Attach window to MCP server so it can push IPC events to renderer
  const mainWin = windowManager.getMainWindow();
  if (mainWin) {
    mcpServer.setMainWindow(mainWin);
  }

  // Create system tray
  trayManager = new TrayManager(windowManager, containerManager);
  trayManager.create();

  console.log(`[${APP_NAME}] Ready.`);
});

// macOS: re-create window when dock icon clicked
app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    void windowManager?.createMainWindow();
  }
});

// Quit when all windows closed (except macOS — app stays in tray)
app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    // On macOS, the app stays in the tray. On other platforms, quit.
    // But since we want tray behavior everywhere, we keep the app alive.
  }
});

// Graceful shutdown
app.on("before-quit", async () => {
  console.log(`[${APP_NAME}] Shutting down...`);
  sessionManager?.destroy();
  trayManager?.destroy();
  if (mcpServer) {
    await mcpServer.stop();
  }
});

// Second instance tried to launch — bring existing window to front
app.on("second-instance", () => {
  windowManager?.focusMainWindow();
});
