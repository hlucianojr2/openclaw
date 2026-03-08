/**
 * MCP Bridge — internal type definitions.
 *
 * These types are used exclusively within the main process (Express server,
 * policy engine, IPC handlers). They are NOT exposed directly to the renderer;
 * renderer-facing types live in src/shared/ipc-types.ts.
 */

// ─── Tool Categories ─────────────────────────────────────────────────────────

/**
 * Logical grouping of MCP tools.
 * Each category has an associated default policy level.
 */
export type McpToolCategory =
  | "filesystem"
  | "clipboard"
  | "browser"
  | "system-info"
  | "notifications"
  | "app-control";

// ─── Approval Levels ─────────────────────────────────────────────────────────

/**
 * How the policy engine resolves a tool call.
 *
 *   auto-approved     — always allowed, no user interaction required
 *   per-use           — user must approve each invocation
 *   path-constrained  — allowed only if path is within workspace; no user prompt
 *   domain-allowlist  — allowed only if URL domain is on the allowlist
 *   blocked           — always denied; no approval pathway
 */
export type McpApprovalLevel =
  | "auto-approved"
  | "per-use"
  | "path-constrained"
  | "domain-allowlist"
  | "blocked";

// ─── Policy ──────────────────────────────────────────────────────────────────

/** Persistent policy record for one tool category. */
export interface McpPolicy {
  category: McpToolCategory;
  level: McpApprovalLevel;
  /** Domain allowlist (used when level === "domain-allowlist"). */
  allowedDomains: string[];
  /** Workspace path constraint (used when level === "path-constrained"). */
  workspacePath: string;
  updatedAt: string; // ISO timestamp
}

// ─── Policy Evaluation ───────────────────────────────────────────────────────

/** Possible outcomes of the policy engine. */
export type PolicyOutcome =
  | "auto-approved"
  | "needs-approval"
  | "blocked";

/** Result returned by the policy engine for a given tool call. */
export interface PolicyDecision {
  outcome: PolicyOutcome;
  /** Present when blocked or path/domain rejected to explain why. */
  reason?: string;
}

// ─── Tool Calls ──────────────────────────────────────────────────────────────

/** Validated, parsed request body from the HTTP endpoint. */
export interface McpToolCall {
  /** Tool name (e.g. "read_file"). */
  toolName: string;
  /** Resolved category for this tool. */
  category: McpToolCategory;
  /** Agent identifier derived from the bearer token. */
  agentId: string;
  /** Caller-provided arguments (shape depends on tool). */
  args: Record<string, unknown>;
  /** Monotonic timestamp when the call was received. */
  receivedAt: number;
}

// ─── Pending Requests ────────────────────────────────────────────────────────

/** Lifecycle state of an approval request. */
export type McpRequestState =
  | "pending"   // awaiting user decision
  | "approved"  // user approved
  | "denied"    // user denied
  | "expired"   // 60s timeout elapsed
  | "auto";     // resolved automatically (auto-approved)

/** An approval request that the user can act on in the UI. */
export interface McpPendingRequest {
  id: string;
  toolName: string;
  category: McpToolCategory;
  agentId: string;
  /** Sanitized args (no sensitive values in the preview). */
  argsPreview: Record<string, unknown>;
  state: McpRequestState;
  receivedAt: number;
  resolvedAt?: number;
}

// ─── Tool Results ─────────────────────────────────────────────────────────────

/** Successful result from a tool handler. */
export interface McpToolResult {
  data: unknown;
}

// ─── Audit Log ───────────────────────────────────────────────────────────────

/** Outcome stored in the audit log. */
export type McpOutcome = "approved" | "denied" | "blocked" | "expired" | "error";

/** Single audit log entry written after each tool call resolution. */
export interface McpAuditEntry {
  id: string;
  toolName: string;
  category: McpToolCategory;
  agentId: string;
  outcome: McpOutcome;
  /** Error message if outcome === "error". Never includes stack traces. */
  errorMessage?: string;
  timestamp: string; // ISO
}

// ─── Bridge Status ────────────────────────────────────────────────────────────

/** Real-time status of the MCP Bridge Server. */
export interface McpBridgeStatus {
  running: boolean;
  port: number;
  pendingCount: number;
  todayApproved: number;
  todayDenied: number;
  todayBlocked: number;
}

// ─── Tool Name → Category Map ────────────────────────────────────────────────

/** Canonical mapping from tool name to category. */
export const TOOL_CATEGORY_MAP: Readonly<Record<string, McpToolCategory>> = {
  read_file: "filesystem",
  write_file: "filesystem",
  list_dir: "filesystem",
  create_dir: "filesystem",
  read_clipboard: "clipboard",
  write_clipboard: "clipboard",
  open_url: "browser",
  get_system_info: "system-info",
  show_notification: "notifications",
  open_app: "app-control",
  focus_app: "app-control",
} as const;

/** Default approval levels per category (must match architecture spec). */
export const DEFAULT_POLICY_LEVELS: Readonly<Record<McpToolCategory, McpApprovalLevel>> = {
  filesystem: "path-constrained",
  clipboard: "per-use",
  browser: "domain-allowlist",
  "system-info": "auto-approved",
  notifications: "auto-approved",
  "app-control": "per-use",
} as const;

/** Request approval timeout in milliseconds (60 seconds). */
export const APPROVAL_TIMEOUT_MS = 60_000;

/** Maximum concurrent pending requests per agent. */
export const MAX_PENDING_PER_AGENT = 20;
