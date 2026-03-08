/**
 * MCP Bridge IPC Handlers — wires McpBridgeServer to IPC channels.
 *
 * Channel security:
 *   MCP_GET_STATUS    — requires session (mcp:view)
 *   MCP_GET_PENDING   — requires session (mcp:view)
 *   MCP_APPROVE       — requires session (mcp:approve)
 *   MCP_DENY          — requires session (mcp:approve)
 *   MCP_GET_POLICIES  — requires session (mcp:view)
 *   MCP_SET_POLICY    — requires elevated session (mcp:policy-write)
 *   MCP_GET_AUDIT_LOG — requires session (mcp:view)
 */

import { ipcMain } from "electron";
import { IPC_CHANNELS } from "../../shared/ipc-types.js";
import type { SessionManager } from "../auth/session-manager.js";
import { hasPermission } from "../auth/rbac.js";
import type { McpBridgeServer } from "./mcp-server.js";
import type { McpPolicyStore } from "./mcp-policy-store.js";
import type { McpAuditLogger } from "./mcp-audit-logger.js";
import type { McpToolCategory, McpApprovalLevel } from "./mcp-types.js";

// ─── Session Guards ───────────────────────────────────────────────────────────

function requireMcpView(token: string, sessions: SessionManager) {
  const session = sessions.resolve(token);
  if (!session || !hasPermission(session.role, "mcp:view")) {
    throw new Error("Unauthorized");
  }
  return session;
}

function requireMcpApprove(token: string, sessions: SessionManager) {
  const session = sessions.resolve(token);
  if (!session || !hasPermission(session.role, "mcp:approve")) {
    throw new Error("Unauthorized");
  }
  return session;
}

function requireMcpPolicyWrite(token: string, sessions: SessionManager) {
  const session = sessions.resolve(token);
  if (!session || !hasPermission(session.role, "mcp:policy-write")) {
    throw new Error("Unauthorized");
  }
  if (!session.elevated) {
    throw new Error("Elevation required to modify MCP policies");
  }
  return session;
}

// ─── Handler Registration ─────────────────────────────────────────────────────

/**
 * Registers all MCP IPC handlers.
 *
 * @param server - The running McpBridgeServer instance.
 * @param policyStore - The policy store shared with the server.
 * @param auditLogger - The audit logger shared with the server.
 * @param sessions - The application session manager.
 */
export function registerMcpIpcHandlers(
  server: McpBridgeServer,
  policyStore: McpPolicyStore,
  auditLogger: McpAuditLogger,
  sessions: SessionManager,
): void {
  // ─── Status ──────────────────────────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.MCP_GET_STATUS, (_event, token: unknown) => {
    if (typeof token !== "string") { throw new Error("Unauthorized"); }
    requireMcpView(token, sessions);
    return server.getStatus();
  });

  // ─── Pending Requests ────────────────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.MCP_GET_PENDING, (_event, token: unknown) => {
    if (typeof token !== "string") { throw new Error("Unauthorized"); }
    requireMcpView(token, sessions);
    return server.getPendingRequests();
  });

  // ─── Approve ─────────────────────────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.MCP_APPROVE, (_event, token: unknown, requestId: unknown) => {
    if (typeof token !== "string") { throw new Error("Unauthorized"); }
    requireMcpApprove(token, sessions);
    if (typeof requestId !== "string" || !requestId) {
      throw new Error("requestId must be a non-empty string");
    }
    const ok = server.approveRequest(requestId);
    return { ok };
  });

  // ─── Deny ─────────────────────────────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.MCP_DENY, (_event, token: unknown, requestId: unknown) => {
    if (typeof token !== "string") { throw new Error("Unauthorized"); }
    requireMcpApprove(token, sessions);
    if (typeof requestId !== "string" || !requestId) {
      throw new Error("requestId must be a non-empty string");
    }
    const ok = server.denyRequest(requestId);
    return { ok };
  });

  // ─── Get Policies ─────────────────────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.MCP_GET_POLICIES, (_event, token: unknown) => {
    if (typeof token !== "string") { throw new Error("Unauthorized"); }
    requireMcpView(token, sessions);
    return policyStore.getAllPolicies();
  });

  // ─── Set Policy ───────────────────────────────────────────────────────────

  ipcMain.handle(
    IPC_CHANNELS.MCP_SET_POLICY,
    (_event, token: unknown, category: unknown, updates: unknown) => {
      if (typeof token !== "string") { throw new Error("Unauthorized"); }
      requireMcpPolicyWrite(token, sessions);

      if (!isValidCategory(category)) {
        throw new Error(`Invalid category: ${String(category)}`);
      }

      const safeUpdates = extractPolicyUpdates(updates);
      return policyStore.setPolicy(category, safeUpdates);
    },
  );

  // ─── Audit Log ────────────────────────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.MCP_GET_AUDIT_LOG, (_event, token: unknown, limit: unknown) => {
    if (typeof token !== "string") { throw new Error("Unauthorized"); }
    requireMcpView(token, sessions);
    const effectiveLimit = typeof limit === "number" && limit > 0 ? Math.min(limit, 500) : 100;
    return auditLogger.query({ limit: effectiveLimit });
  });
}

// ─── Validation Helpers ───────────────────────────────────────────────────────

const VALID_CATEGORIES = new Set<McpToolCategory>([
  "filesystem",
  "clipboard",
  "browser",
  "system-info",
  "notifications",
  "app-control",
]);

const VALID_LEVELS = new Set<McpApprovalLevel>([
  "auto-approved",
  "per-use",
  "path-constrained",
  "domain-allowlist",
  "blocked",
]);

function isValidCategory(value: unknown): value is McpToolCategory {
  return typeof value === "string" && VALID_CATEGORIES.has(value as McpToolCategory);
}

function extractPolicyUpdates(value: unknown): {
  level?: McpApprovalLevel;
  allowedDomains?: string[];
  workspacePath?: string;
} {
  if (typeof value !== "object" || value === null) {
    throw new Error("Policy updates must be an object");
  }
  const obj = value as Record<string, unknown>;
  const result: {
    level?: McpApprovalLevel;
    allowedDomains?: string[];
    workspacePath?: string;
  } = {};

  if (obj["level"] !== undefined) {
    if (!VALID_LEVELS.has(obj["level"] as McpApprovalLevel)) {
      throw new Error(`Invalid policy level: ${JSON.stringify(obj["level"])}`);
    }
    result.level = obj["level"] as McpApprovalLevel;
  }

  if (obj["allowedDomains"] !== undefined) {
    if (!Array.isArray(obj["allowedDomains"])) {
      throw new Error("allowedDomains must be an array");
    }
    const domains = obj["allowedDomains"] as unknown[];
    if (domains.some((d) => typeof d !== "string")) {
      throw new Error("allowedDomains must contain only strings");
    }
    // Sanitize domains: lowercase, no leading dots, max 253 chars
    result.allowedDomains = (domains as string[]).map((d) =>
      d.toLowerCase().replace(/^\.+/, "").slice(0, 253),
    );
  }

  if (obj["workspacePath"] !== undefined) {
    if (typeof obj["workspacePath"] !== "string") {
      throw new Error("workspacePath must be a string");
    }
    if (obj["workspacePath"].includes("\0")) {
      throw new Error("workspacePath must not contain null bytes");
    }
    result.workspacePath = obj["workspacePath"];
  }

  return result;
}
