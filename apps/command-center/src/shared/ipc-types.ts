/**
 * OpenClaw Command Center — Shared types for IPC bridge.
 *
 * These types define the contract between the main process and the renderer.
 * The preload script exposes a typed subset of these via `window.occc`.
 */

// ─── Environment Status ─────────────────────────────────────────────────────

export type EnvironmentHealth = "healthy" | "degraded" | "unhealthy" | "stopped" | "unknown";

export interface EnvironmentStatus {
  health: EnvironmentHealth;
  gateway: ContainerStatus;
  cli: ContainerStatus;
  sandboxes: ContainerStatus[];
  uptime: number | null;
}

export interface ContainerStatus {
  id: string;
  name: string;
  state: "running" | "paused" | "stopped" | "restarting" | "removing" | "dead" | "created";
  health: EnvironmentHealth;
  cpu: number;
  memoryMB: number;
  networkRx: number;
  networkTx: number;
}

// ─── System Validation ──────────────────────────────────────────────────────

export type CheckResult = "pass" | "warn" | "fail";

export interface SystemCheck {
  name: string;
  description: string;
  result: CheckResult;
  message: string;
  autoFixAvailable: boolean;
}

export interface SystemValidation {
  checks: SystemCheck[];
  allPassed: boolean;
  canProceed: boolean;
}

// ─── Docker Engine ──────────────────────────────────────────────────────────

export type DockerVariant = "docker-desktop" | "docker-ce" | "podman" | "none";

export interface DockerInfo {
  variant: DockerVariant;
  version: string;
  apiVersion: string;
  running: boolean;
}

// ─── Configuration ──────────────────────────────────────────────────────────

/** Field types the renderer can render. */
export type ConfigFieldType =
  | "text"
  | "password"
  | "number"
  | "boolean"
  | "select"
  | "string-array"
  | "record"
  | "json";

export interface ConfigSection {
  key: string;
  label: string;
  description: string;
  fields: ConfigField[];
}

export interface ConfigField {
  key: string;
  label: string;
  type: ConfigFieldType;
  value: unknown;
  defaultValue: unknown;
  options?: { label: string; value: string }[];
  required: boolean;
  sensitive: boolean;
  description: string;
  /** Numeric minimum constraint. */
  min?: number;
  /** Numeric maximum constraint. */
  max?: number;
  /** Full dotted path in the config tree (e.g. ["gateway", "auth", "mode"]). */
  path?: string[];
  /** For text fields: render as multiline textarea. */
  multiline?: boolean;
  /** Placeholder hint text. */
  placeholder?: string;
}

/** Result of reading the config file. */
export interface ConfigReadResult {
  config: Record<string, unknown>;
  checksum: string;
  configPath: string;
}

/** Result of writing the config file. */
export interface ConfigWriteResult {
  ok: boolean;
  error?: string;
  checksum: string;
}

/** Result of validating config against the Zod schema. */
export interface ConfigValidationResult {
  valid: boolean;
  errors: { path: string; message: string }[];
  /** Present when schema validation is unavailable in this environment. */
  note?: string;
}

/** A single change between saved and pending config. */
export interface ConfigDiffEntry {
  /** Dotted path (e.g. "gateway.port"). */
  path: string;
  type: "added" | "removed" | "changed";
  oldValue?: unknown;
  newValue?: unknown;
}

// ─── Skills ─────────────────────────────────────────────────────────────────

export type SkillRiskLevel = "low" | "medium" | "high" | "blocked";
export type SkillApprovalStatus = "approved" | "pending" | "rejected" | "blocked";

export interface SkillInfo {
  name: string;
  description: string;
  riskLevel: SkillRiskLevel;
  approvalStatus: SkillApprovalStatus;
  installed: boolean;
  scanFindings: number;
}

// ─── Skill Catalog (Wizard Step 6) ──────────────────────────────────────────

/**
 * Approval level for wizard-time skill selection.
 *   auto-approved — installed immediately, no prompt
 *   user-ack      — user must acknowledge before install
 *   admin-review  — requires elevated session + AI scan before install
 *   blocked       — never permitted
 */
export type SkillApprovalLevel = "auto-approved" | "user-ack" | "admin-review" | "blocked";

/** Extension category tag (used in skill-catalog). */
export type SkillCategory =
  | "monitoring"
  | "analytics"
  | "productivity"
  | "utilities"
  | "development"
  | "communication"
  | "system";

export interface SkillCatalogEntry {
  /** Unique skill identifier (matches extension dir name). */
  id: string;
  name: string;
  description: string;
  riskLevel: SkillRiskLevel;
  approvalLevel: SkillApprovalLevel;
  /** Pre-selected/recommended in the wizard. */
  recommended: boolean;
  /** Whether this skill needs a third-party API key. */
  requiresApiKey: boolean;
  apiKeyLabel?: string;
  officialLink?: string;
  category: SkillCategory;
}

// ─── Channel Catalog (Wizard Step 7) ─────────────────────────────────────────

export type ChannelCategory = "messaging" | "team-chat" | "email" | "voice" | "social" | "dev";

/** A single config field shown in the channel setup form. */
export interface ChannelConfigField {
  key: string;
  label: string;
  type: "text" | "password" | "number";
  description: string;
  required: boolean;
  placeholder?: string;
}

export interface ChannelCatalogEntry {
  /** Unique channel identifier (matches extension/built-in dir name). */
  id: string;
  name: string;
  description: string;
  category: ChannelCategory;
  /** Pre-selected/recommended in the wizard. */
  recommended: boolean;
  /** Whether the channel requires external app/bot setup. */
  requiresAppSetup: boolean;
  setupGuideUrl?: string;
  requiredFields: ChannelConfigField[];
  /** Built into OpenClaw core (no extension install needed). */
  builtin: boolean;
}

/** Channel + its config values as collected by the wizard. */
export interface ChannelSelection {
  channelId: string;
  config: Record<string, string>;
}

// ─── Auth & RBAC ────────────────────────────────────────────────────────────

export type UserRole = "super-admin" | "admin" | "operator" | "viewer";

export interface UserProfile {
  id: string;
  username: string;
  role: UserRole;
  biometricEnrolled: boolean;
  totpEnabled: boolean;
  createdAt: string;
  lastLoginAt: string | null;
}

export interface AuthSession {
  userId: string;
  role: UserRole;
  authenticatedAt: number;
  expiresAt: number;
  elevated: boolean;
}

export interface TotpSetupInfo {
  secret: string;
  otpAuthUrl: string;
  qrDataUrl: string;
}

export interface CreateUserParams {
  username: string;
  role: UserRole;
  password: string;
}

export interface MutationResult {
  ok: boolean;
  reason?: string;
}

export interface AuditLogEntry {
  id: string;
  userId: string | null;
  username: string | null;
  event: string;
  method: string | null;
  success: boolean;
  timestamp: string;
}

// ─── IPC Channel Definitions ────────────────────────────────────────────────

/**
 * IPC channels used between main process and renderer.
 * All channels follow the pattern: "occc:<domain>:<action>"
 */
export const IPC_CHANNELS = {
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
  DOCKER_INSTALL_CHECK: "occc:docker:install-check",

  // Config
  CONFIG_GET: "occc:config:get",
  CONFIG_SET: "occc:config:set",
  CONFIG_VALIDATE: "occc:config:validate",
  CONFIG_SECTIONS: "occc:config:sections",
  CONFIG_READ: "occc:config:read",
  CONFIG_WRITE: "occc:config:write",
  CONFIG_PATH: "occc:config:path",
  CONFIG_SCHEMA: "occc:config:schema",
  CONFIG_RELOAD: "occc:config:reload",
  CONFIG_DIFF: "occc:config:diff",

  // Skills
  SKILLS_LIST: "occc:skills:list",
  SKILLS_INSTALL: "occc:skills:install",
  SKILLS_SCAN: "occc:skills:scan",

  // System
  SYSTEM_VALIDATE: "occc:system:validate",
  SYSTEM_PLATFORM: "occc:system:platform",

  // Backup
  BACKUP_CREATE: "occc:backup:create",
  BACKUP_RESTORE: "occc:backup:restore",
  BACKUP_HISTORY: "occc:backup:history",

  // Installer (pre-auth setup wizard)
  INSTALL_VALIDATE_SYSTEM: "occc:install:validate-system",
  INSTALL_DOCKER_OPTIONS: "occc:install:docker-options",
  INSTALL_OPEN_DOCKER_DOWNLOAD: "occc:install:open-docker-download",
  INSTALL_DOCKER_CE_COMMAND: "occc:install:docker-ce-command",
  INSTALL_START_DOCKER_DESKTOP: "occc:install:start-docker-desktop",
  INSTALL_VERIFY_DOCKER: "occc:install:verify-docker",
  INSTALL_VOICE_SPEAK: "occc:install:voice-speak",
  INSTALL_VOICE_SET_ENABLED: "occc:install:voice-set-enabled",
  INSTALL_VOICE_STOP: "occc:install:voice-stop",
  INSTALL_GITHUB_VALIDATE_PAT: "occc:install:github-validate-pat",
  INSTALL_GITHUB_CHECK_SCOPE: "occc:install:github-check-scope",
  INSTALL_GITHUB_CREATE_REPO: "occc:install:github-create-repo",
  INSTALL_RUN: "occc:install:run",
  INSTALL_PROGRESS: "occc:install:progress",

  // Installer — Skill & Channel Catalog (wizard steps 6–7)
  INSTALL_GET_SKILL_CATALOG: "occc:install:get-skill-catalog",
  INSTALL_GET_CHANNEL_CATALOG: "occc:install:get-channel-catalog",
  INSTALL_CHANNEL_VALIDATE: "occc:install:channel-validate",
} as const;

// ─── API Bridge Type ────────────────────────────────────────────────────────

/**
 * The typed API surface exposed to the renderer via `window.occc`.
 */
export interface OcccBridge {
  // Auth
  login(username: string, password: string): Promise<{ session: AuthSession; token: string } | { requiresTotp: true; nonce: string } | null>;
  biometricAuth(username: string): Promise<{ session: AuthSession; token: string } | null>;
  verifyTotp(nonce: string, code: string): Promise<{ session: AuthSession; token: string } | null>;
  logout(token?: string): Promise<void>;
  getSession(token?: string): Promise<AuthSession | null>;
  elevate(token?: string, totpCode?: string): Promise<{ ok: boolean; reason?: string } | null>;

  // Auth — First Run
  isFirstRun(): Promise<boolean>;
  createInitialUser(username: string, password: string): Promise<{ profile: UserProfile; totpSetup: TotpSetupInfo; recoveryCodes: string[] }>;
  confirmTotp(token: string, code: string): Promise<boolean>;
  isBiometricAvailable(): Promise<boolean>;
  enrollBiometric(token: string): Promise<boolean>;

  // Auth — User Management (admin+, elevation required for mutations)
  listUsers(token: string): Promise<UserProfile[]>;
  createUser(token: string, params: CreateUserParams): Promise<UserProfile>;
  updateUserRole(token: string, userId: string, role: UserRole): Promise<MutationResult>;
  resetUserPassword(token: string, userId: string, newPassword: string): Promise<MutationResult>;
  deleteUser(token: string, userId: string): Promise<MutationResult>;
  getAuditLog(token: string, limit?: number): Promise<AuditLogEntry[]>;

  // Auth — Self-service
  changePassword(token: string, currentPassword: string, newPassword: string): Promise<MutationResult & { newToken?: string }>;

  // Environment (session required; create/destroy require elevated session)
  getEnvironmentStatus(token: string): Promise<EnvironmentStatus>;
  createEnvironment(token: string, config: Record<string, unknown>): Promise<void>;
  startEnvironment(token: string): Promise<void>;
  stopEnvironment(token: string): Promise<void>;
  destroyEnvironment(token: string): Promise<void>;
  getEnvironmentLogs(token: string, containerId: string): Promise<string>;

  // Docker
  getDockerInfo(): Promise<DockerInfo>;

  // Config (session required)
  getConfigSections(token: string): Promise<ConfigSection[]>;
  getConfig(token: string, section: string): Promise<Record<string, unknown>>;
  setConfig(token: string, section: string, values: Record<string, unknown>): Promise<void>;

  // Config — Phase 4 typed methods (session required; write ops need elevation)
  readConfig(token: string): Promise<ConfigReadResult>;
  writeConfig(token: string, config: Record<string, unknown>, checksum?: string): Promise<ConfigWriteResult>;
  validateConfig(token: string, config: Record<string, unknown>): Promise<ConfigValidationResult>;
  getConfigPath(token: string): Promise<string>;
  getConfigSchema(token: string): Promise<ConfigSection[]>;
  reloadConfig(token: string): Promise<{ ok: boolean; error?: string }>;
  getConfigDiff(token: string, pending: Record<string, unknown>): Promise<ConfigDiffEntry[]>;

  // Skills (session required)
  listSkills(token: string): Promise<SkillInfo[]>;
  installSkill(name: string): Promise<void>;
  scanSkill(path: string): Promise<{ approved: boolean; findings: string[] }>;

  // System
  validateSystem(): Promise<SystemValidation>;
  getPlatform(): Promise<{ os: string; arch: string; version: string }>;

  // Backup
  createBackup(): Promise<void>;
  getBackupHistory(): Promise<{ timestamp: string; commit: string }[]>;

  // Installer (pre-auth setup wizard — no token required)
  installValidateSystem(): Promise<SystemValidation>;
  installGetDockerOptions(): Promise<{ dockerDesktop: boolean; dockerCE: boolean }>;
  installOpenDockerDownload(): Promise<void>;
  installGetDockerCECommand(): Promise<string>;
  installStartDockerDesktop(): Promise<boolean>;
  installVerifyDocker(): Promise<{ ok: boolean; version?: string; error?: string }>;
  installVoiceSpeak(text: string): Promise<void>;
  installVoiceSetEnabled(enabled: boolean): Promise<boolean>;
  installVoiceStop(): Promise<void>;
  installGitHubValidatePAT(pat: string): Promise<{ valid: boolean; login?: string }>;
  installGitHubCheckScope(pat: string): Promise<{ hasScope: boolean }>;
  installGitHubCreateRepo(pat: string): Promise<{ url: string }>;
  installRun(config: Record<string, unknown>): Promise<void>;

  // Installer — Skill & Channel Catalog (wizard steps 6–7)
  installGetSkillCatalog(): Promise<SkillCatalogEntry[]>;
  installGetChannelCatalog(): Promise<ChannelCatalogEntry[]>;
  installChannelValidate(channelId: string, config: Record<string, string>): Promise<{ valid: boolean; error?: string }>;

  // Events
  on(channel: string, callback: (...args: unknown[]) => void): void;
  off(channel: string, callback: (...args: unknown[]) => void): void;

  /**
   * @deprecated Dev-only scaffold for auth/install channels not yet added to the
   * typed bridge. Rejected in production builds by the preload. Do NOT add new
   * usages — add a typed OcccBridge method instead.
   */
  invoke(channel: string, ...args: unknown[]): Promise<unknown>;
}
