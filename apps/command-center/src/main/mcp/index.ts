/**
 * MCP Bridge — public API re-exports.
 *
 * Import from this module to use the MCP bridge subsystem.
 */

export { McpBridgeServer } from "./mcp-server.js";
export { McpPolicyStore } from "./mcp-policy-store.js";
export { McpAuditLogger } from "./mcp-audit-logger.js";
export { registerMcpIpcHandlers } from "./mcp-ipc.js";
export { evaluatePolicy } from "./mcp-policy-engine.js";
export { TOOL_HANDLERS } from "./mcp-tool-handlers.js";
export type {
  McpToolCategory,
  McpApprovalLevel,
  McpPolicy,
  McpPendingRequest,
  McpToolCall,
  McpToolResult,
  McpAuditEntry,
  McpOutcome,
  McpBridgeStatus,
  PolicyDecision,
  PolicyOutcome,
} from "./mcp-types.js";
