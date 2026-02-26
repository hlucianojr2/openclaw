/**
 * Application-wide constants.
 */

/** App identifier for system-level registration. */
export const APP_ID = "ai.openclaw.command-center";
export const APP_NAME = "OpenClaw Command Center";
export const APP_SHORT_NAME = "OCCC";

/** Default ports used by the OpenClaw gateway/bridge. */
export const DEFAULT_GATEWAY_PORT = 18789;
export const DEFAULT_BRIDGE_PORT = 18790;

/** MCP Bridge server port (host-side, for container→host requests). */
export const DEFAULT_MCP_BRIDGE_PORT = 18791;

/** REST API server port. */
export const DEFAULT_API_PORT = 18800;

/** Auth session timeout in milliseconds (30 minutes). */
export const AUTH_SESSION_TIMEOUT_MS = 30 * 60 * 1000;

/** Container integrity check interval in milliseconds (5 minutes). */
export const INTEGRITY_CHECK_INTERVAL_MS = 5 * 60 * 1000;

/** Backup schedule — daily at 3 AM local time. */
export const BACKUP_CRON = "0 3 * * *";

/** Docker image name used for OpenClaw containers. */
export const OPENCLAW_IMAGE = "openclaw:local";

/** User-facing names (never expose Docker terminology). */
export const USER_FACING = {
  environment: "OpenClaw Environment",
  gateway: "Core Service",
  cli: "Agent Terminal",
  sandbox: "Agent Workspace",
  container: "Service",
  image: "Package",
  volume: "Storage",
} as const;

/** LLM provider priority cascade. */
export const LLM_PRIORITY = [
  "anthropic",
  "google-gemini",
  "openai",
  "ollama",
] as const;

export type LLMProvider = (typeof LLM_PRIORITY)[number];

/** RBAC role hierarchy (higher index = more permissions). */
export const ROLE_HIERARCHY: Record<string, number> = {
  viewer: 0,
  operator: 1,
  admin: 2,
  "super-admin": 3,
};

// ─── Config Center Tab Definitions ──────────────────────────────────────────

/** Stable identifiers for each configuration tab. */
export type ConfigTabId =
  | "gateway"
  | "agents"
  | "channels"
  | "providers"
  | "tools"
  | "tts"
  | "hooks"
  | "security"
  | "system"
  | "advanced";

export interface ConfigTab {
  id: ConfigTabId;
  label: string;
  icon: string;
  description: string;
}

/** Static list of configuration tabs shown in the renderer sidebar. */
export const CONFIG_TABS: readonly ConfigTab[] = [
  { id: "gateway", label: "Gateway", icon: "server", description: "Server, auth, and network settings" },
  { id: "agents", label: "Agents", icon: "bot", description: "Agent configuration and defaults" },
  { id: "channels", label: "Channels", icon: "message-square", description: "Messaging channel adapters" },
  { id: "providers", label: "Providers", icon: "cloud", description: "LLM and AI provider keys" },
  { id: "tools", label: "Tools", icon: "wrench", description: "Tool permissions and settings" },
  { id: "tts", label: "TTS", icon: "volume-2", description: "Text-to-speech configuration" },
  { id: "hooks", label: "Hooks", icon: "webhook", description: "Lifecycle hooks and scripts" },
  { id: "security", label: "Security", icon: "shield", description: "RBAC, tokens, and trust settings" },
  { id: "system", label: "System", icon: "settings", description: "Logging, paths, and runtime options" },
  { id: "advanced", label: "Advanced", icon: "code", description: "Raw config editor and JSON view" },
] as const;
