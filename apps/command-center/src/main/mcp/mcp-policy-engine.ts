/**
 * MCP Policy Engine — evaluates a tool call against the active policy.
 *
 * Rules:
 *   auto-approved     → outcome: "auto-approved" (no user interaction)
 *   per-use           → outcome: "needs-approval"
 *   path-constrained  → resolve realpath, check prefix; auto-approved if ok, blocked if not
 *   domain-allowlist  → check URL domain against allowlist; auto-approved if ok, blocked if not
 *   blocked           → outcome: "blocked"
 */

import { realpath } from "node:fs/promises";
import { URL } from "node:url";
import type { McpToolCall, PolicyDecision } from "./mcp-types.js";
import type { McpPolicyStore } from "./mcp-policy-store.js";

// Schemes that are never permitted for the browser tool
const BLOCKED_URL_SCHEMES = new Set(["file:", "javascript:", "data:"]);

/**
 * Evaluates a tool call against its category policy.
 *
 * @param call - The validated tool call.
 * @param policyStore - The policy store to consult.
 * @returns A PolicyDecision indicating the outcome.
 */
export async function evaluatePolicy(
  call: McpToolCall,
  policyStore: McpPolicyStore,
): Promise<PolicyDecision> {
  const policy = policyStore.getPolicy(call.category);

  switch (policy.level) {
    case "auto-approved":
      return { outcome: "auto-approved" };

    case "per-use":
      return { outcome: "needs-approval" };

    case "blocked":
      return { outcome: "blocked", reason: `Category "${call.category}" is blocked by policy` };

    case "path-constrained":
      return evaluatePathConstraint(call, policy.workspacePath);

    case "domain-allowlist":
      return evaluateDomainAllowlist(call, policy.allowedDomains);

    default: {
      // Exhaustiveness guard — treat unknown levels as blocked
      const _exhaustive: never = policy.level;
      void _exhaustive;
      return { outcome: "blocked", reason: "Unknown policy level" };
    }
  }
}

// ─── Path Constraint ─────────────────────────────────────────────────────────

/**
 * Validates that the "path" arg (if present) resolves to within workspacePath.
 * Uses fs.realpath() to resolve symlinks — prevents symlink escape.
 *
 * If no workspacePath is configured, falls back to needs-approval.
 * If no "path" arg is present in args, falls back to needs-approval.
 */
async function evaluatePathConstraint(
  call: McpToolCall,
  workspacePath: string,
): Promise<PolicyDecision> {
  if (!workspacePath) {
    // No workspace configured — need explicit user approval
    return { outcome: "needs-approval" };
  }

  const rawPath = call.args["path"];
  if (typeof rawPath !== "string" || !rawPath) {
    return { outcome: "needs-approval" };
  }

  try {
    // Resolve both paths to their canonical real paths to handle symlinks
    const [resolvedPath, resolvedWorkspace] = await Promise.all([
      realpath(rawPath).catch(() => rawPath),  // file may not exist yet (create_dir, write_file)
      realpath(workspacePath),
    ]);

    const normalizedWorkspace = resolvedWorkspace.endsWith("/")
      ? resolvedWorkspace
      : resolvedWorkspace + "/";

    if (resolvedPath === resolvedWorkspace || resolvedPath.startsWith(normalizedWorkspace)) {
      return { outcome: "auto-approved" };
    }

    return {
      outcome: "blocked",
      reason: `Path "${rawPath}" is outside the permitted workspace`,
    };
  } catch {
    // If realpath fails (workspacePath doesn't exist), block for safety
    return {
      outcome: "blocked",
      reason: "Could not resolve workspace path — access denied",
    };
  }
}

// ─── Domain Allowlist ────────────────────────────────────────────────────────

/**
 * Validates that the "url" arg uses http/https and its hostname is on the allowlist.
 * Blocks file:, javascript:, and data: schemes unconditionally.
 */
function evaluateDomainAllowlist(
  call: McpToolCall,
  allowedDomains: string[],
): PolicyDecision {
  const rawUrl = call.args["url"];
  if (typeof rawUrl !== "string" || !rawUrl) {
    return { outcome: "blocked", reason: "No URL provided for browser tool" };
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { outcome: "blocked", reason: "Invalid URL format" };
  }

  if (BLOCKED_URL_SCHEMES.has(parsed.protocol)) {
    return {
      outcome: "blocked",
      reason: `URL scheme "${parsed.protocol}" is not permitted`,
    };
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return {
      outcome: "blocked",
      reason: `URL scheme "${parsed.protocol}" is not permitted — only http and https are allowed`,
    };
  }

  if (allowedDomains.length === 0) {
    return {
      outcome: "blocked",
      reason: "No domains are on the browser allowlist — add domains in MCP Bridge settings",
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const isAllowed = allowedDomains.some((allowed) => {
    const norm = allowed.toLowerCase();
    return hostname === norm || hostname.endsWith("." + norm);
  });

  if (isAllowed) {
    return { outcome: "auto-approved" };
  }

  return {
    outcome: "blocked",
    reason: `Domain "${hostname}" is not on the browser allowlist`,
  };
}
