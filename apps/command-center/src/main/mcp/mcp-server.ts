/**
 * MCP Bridge Server — Express HTTP server on 127.0.0.1:18791.
 *
 * Containerized agents POST to /tool/:name with a bearer token.
 * The policy engine evaluates each call and either:
 *   - auto-approves it (returns result immediately)
 *   - queues it for user approval (waits up to 60s)
 *   - blocks it (returns 403)
 *
 * Security:
 *   - Binds to 127.0.0.1 ONLY (not 0.0.0.0)
 *   - Bearer token validated with crypto.timingSafeEqual
 *   - Max 20 pending requests per agent (503 on overflow)
 *   - 60s approval timeout (408)
 *   - No credential values in logs or error responses
 *
 * The server emits events for IPC bridging:
 *   "request" — new pending request created
 *   "resolved" — request approved, denied, or expired
 */

import express, { type Request, type Response } from "express";
import type { Server } from "node:http";
import { createServer } from "node:http";
import { timingSafeEqual, randomBytes } from "node:crypto";
import { EventEmitter } from "node:events";
import type { BrowserWindow } from "electron";
import { IPC_CHANNELS } from "../../shared/ipc-types.js";
import { DEFAULT_MCP_BRIDGE_PORT } from "../../shared/constants.js";
import type {
  McpToolCall,
  McpPendingRequest,
  McpBridgeStatus,
  McpOutcome,
} from "./mcp-types.js";
import {
  TOOL_CATEGORY_MAP,
  APPROVAL_TIMEOUT_MS,
  MAX_PENDING_PER_AGENT,
} from "./mcp-types.js";
import { evaluatePolicy } from "./mcp-policy-engine.js";
import { TOOL_HANDLERS } from "./mcp-tool-handlers.js";
import type { McpPolicyStore } from "./mcp-policy-store.js";
import type { McpAuditLogger } from "./mcp-audit-logger.js";

// ─── Types ───────────────────────────────────────────────────────────────────

/** Internal pending request with resolve/reject for the HTTP response promise. */
interface PendingEntry {
  request: McpPendingRequest;
  resolve: (approved: boolean) => void;
  timeout: ReturnType<typeof setTimeout>;
}

interface McpServerEvents {
  request: [request: McpPendingRequest];
  resolved: [request: McpPendingRequest];
}

// ─── McpBridgeServer ─────────────────────────────────────────────────────────

/**
 * The MCP Bridge HTTP server.
 *
 * Lifecycle:
 *   const server = new McpBridgeServer(policyStore, auditLogger, bearerToken);
 *   await server.start();
 *   // ... app runs ...
 *   await server.stop();
 */
export class McpBridgeServer extends EventEmitter<McpServerEvents> {
  private app = express();
  private httpServer: Server | null = null;
  private pendingRequests = new Map<string, PendingEntry>();
  private bearerTokenBuf: Buffer;
  private port: number;
  private mainWindow: BrowserWindow | null = null;

  constructor(
    private readonly policyStore: McpPolicyStore,
    private readonly auditLogger: McpAuditLogger,
    bearerToken: string,
    port = DEFAULT_MCP_BRIDGE_PORT,
  ) {
    super();
    if (!bearerToken || bearerToken.length < 16) {
      throw new Error("MCP bearer token must be at least 16 characters");
    }
    this.bearerTokenBuf = Buffer.from(bearerToken, "utf8");
    this.port = port;
    this.setupRoutes();
  }

  /** Attach the main BrowserWindow to enable push IPC events to the renderer. */
  setMainWindow(win: BrowserWindow): void {
    this.mainWindow = win;
  }

  // ─── Server Lifecycle ─────────────────────────────────────────────────────

  /** Start listening on 127.0.0.1 only. */
  start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.httpServer = createServer(this.app);
      this.httpServer.on("error", reject);
      this.httpServer.listen(this.port, "127.0.0.1", () => {
        console.log(`[MCP] Bridge server listening on 127.0.0.1:${this.port}`);
        resolve();
      });
    });
  }

  /** Stop the server and reject all pending requests. */
  async stop(): Promise<void> {
    // Reject all pending requests before shutdown
    for (const [id, entry] of this.pendingRequests) {
      clearTimeout(entry.timeout);
      entry.resolve(false);
      this.pendingRequests.delete(id);
    }

    if (this.httpServer) {
      await new Promise<void>((resolve) => {
        this.httpServer!.close(() => resolve());
      });
      this.httpServer = null;
      console.log("[MCP] Bridge server stopped");
    }
  }

  /** Returns current server status. */
  getStatus(): McpBridgeStatus {
    const today = this.auditLogger.countToday();
    return {
      running: this.httpServer?.listening ?? false,
      port: this.port,
      pendingCount: this.pendingRequests.size,
      todayApproved: today.approved,
      todayDenied: today.denied,
      todayBlocked: today.blocked,
    };
  }

  /** Get all currently pending requests as an array. */
  getPendingRequests(): McpPendingRequest[] {
    return Array.from(this.pendingRequests.values()).map((e) => e.request);
  }

  /**
   * Approve a pending request by ID.
   * Called by IPC handler when user approves.
   * Returns false if the request is not found or already resolved.
   */
  approveRequest(requestId: string): boolean {
    const entry = this.pendingRequests.get(requestId);
    if (!entry || entry.request.state !== "pending") { return false; }

    clearTimeout(entry.timeout);
    entry.request.state = "approved";
    entry.request.resolvedAt = Date.now();
    entry.resolve(true);
    this.pendingRequests.delete(requestId);
    this.emitResolved(entry.request);
    return true;
  }

  /**
   * Deny a pending request by ID.
   * Called by IPC handler when user denies.
   * Returns false if the request is not found or already resolved.
   */
  denyRequest(requestId: string): boolean {
    const entry = this.pendingRequests.get(requestId);
    if (!entry || entry.request.state !== "pending") { return false; }

    clearTimeout(entry.timeout);
    entry.request.state = "denied";
    entry.request.resolvedAt = Date.now();
    entry.resolve(false);
    this.pendingRequests.delete(requestId);
    this.auditLogger.append({
      toolName: entry.request.toolName,
      category: entry.request.category,
      agentId: entry.request.agentId,
      outcome: "denied",
    });
    this.emitResolved(entry.request);
    return true;
  }

  // ─── Route Setup ──────────────────────────────────────────────────────────

  private setupRoutes(): void {
    this.app.use(express.json({ limit: "64kb" }));

    // Health endpoint — no auth required
    this.app.get("/health", (_req: Request, res: Response) => {
      res.json({ status: "ok" });
    });

    // Tool call endpoint
    this.app.post(
      "/tool/:name",
      (req: Request, res: Response) => {
        void this.handleToolRequest(req, res);
      },
    );

    // Catch-all 404
    this.app.use((_req: Request, res: Response) => {
      res.status(404).json({ ok: false, error: "Not found" });
    });
  }

  // ─── Request Handler ──────────────────────────────────────────────────────

  private async handleToolRequest(req: Request, res: Response): Promise<void> {
    // 1. Bearer token validation
    const agentId = this.validateBearer(req);
    if (!agentId) {
      res.status(401).json({ ok: false, error: "Unauthorized" });
      return;
    }

    // 2. Tool name resolution
    const rawName = req.params["name"];
    const toolName = Array.isArray(rawName) ? rawName[0] ?? "" : rawName ?? "";
    const category = TOOL_CATEGORY_MAP[toolName];
    if (!category) {
      res.status(404).json({ ok: false, error: `Unknown tool: ${toolName}` });
      return;
    }

    // 3. Args validation
    const body = req.body as unknown;
    const args = extractArgs(body);
    if (!args) {
      res.status(400).json({ ok: false, error: "Request body must be { args: {} }" });
      return;
    }

    // 4. Per-agent pending cap (20 requests max)
    const pendingForAgent = this.countPendingForAgent(agentId);
    if (pendingForAgent >= MAX_PENDING_PER_AGENT) {
      res.status(503).json({ ok: false, error: "Too many pending requests" });
      return;
    }

    // 5. Build tool call
    const toolCall: McpToolCall = {
      toolName,
      category,
      agentId,
      args,
      receivedAt: Date.now(),
    };

    // 6. Policy evaluation
    let decision;
    try {
      decision = await evaluatePolicy(toolCall, this.policyStore);
    } catch (err: unknown) {
      console.error("[MCP] Policy evaluation error:", err instanceof Error ? err.message : "unknown");
      res.status(500).json({ ok: false, error: "Internal error" });
      return;
    }

    // 7. Route by decision
    if (decision.outcome === "blocked") {
      this.auditLogger.append({ toolName, category, agentId, outcome: "blocked" });
      res.status(403).json({ ok: false, error: "Access denied" });
      return;
    }

    if (decision.outcome === "auto-approved") {
      await this.executeAndRespond(toolCall, "approved", res);
      return;
    }

    // needs-approval: queue and wait
    await this.queueAndWait(toolCall, res);
  }

  // ─── Execution ───────────────────────────────────────────────────────────

  private async executeAndRespond(
    call: McpToolCall,
    outcome: McpOutcome,
    res: Response,
  ): Promise<void> {
    const handler = TOOL_HANDLERS[call.toolName];
    if (!handler) {
      this.auditLogger.append({
        toolName: call.toolName,
        category: call.category,
        agentId: call.agentId,
        outcome: "error",
        errorMessage: "No handler registered",
      });
      res.status(500).json({ ok: false, error: "Internal error" });
      return;
    }

    try {
      const workspacePath = this.policyStore.getPolicy(call.category).workspacePath;
      const result = await handler(call.args, workspacePath);
      this.auditLogger.append({
        toolName: call.toolName,
        category: call.category,
        agentId: call.agentId,
        outcome,
      });
      res.status(200).json({ ok: true, data: result.data });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Tool execution failed";
      // Never log args — they may contain sensitive data
      console.error(`[MCP] Tool ${call.toolName} failed: ${message}`);
      this.auditLogger.append({
        toolName: call.toolName,
        category: call.category,
        agentId: call.agentId,
        outcome: "error",
        errorMessage: message,
      });
      res.status(500).json({ ok: false, error: "Tool execution failed" });
    }
  }

  // ─── Pending Request Queue ────────────────────────────────────────────────

  private queueAndWait(call: McpToolCall, res: Response): Promise<void> {
    return new Promise((resolvePromise) => {
      const requestId = randomBytes(8).toString("hex");
      const pending: McpPendingRequest = {
        id: requestId,
        toolName: call.toolName,
        category: call.category,
        agentId: call.agentId,
        argsPreview: sanitizeArgs(call.args),
        state: "pending",
        receivedAt: call.receivedAt,
      };

      let responseResolved = false;

      const finish = (approved: boolean) => {
        if (responseResolved) { return; }
        responseResolved = true;
        resolvePromise();

        if (approved) {
          void this.executeAndRespond(call, "approved", res);
        } else {
          const state = pending.state;
          if (state === "expired") {
            res.status(408).json({ ok: false, error: "Approval timeout" });
          } else {
            res.status(403).json({ ok: false, error: "Request denied" });
          }
        }
      };

      const timeout = setTimeout(() => {
        pending.state = "expired";
        pending.resolvedAt = Date.now();
        this.pendingRequests.delete(requestId);
        this.auditLogger.append({
          toolName: call.toolName,
          category: call.category,
          agentId: call.agentId,
          outcome: "expired",
        });
        this.emitResolved(pending);
        finish(false);
      }, APPROVAL_TIMEOUT_MS);

      this.pendingRequests.set(requestId, {
        request: pending,
        resolve: finish,
        timeout,
      });

      // Notify renderer of new pending request
      this.emitRequest(pending);
    });
  }

  // ─── IPC Push Events ──────────────────────────────────────────────────────

  private emitRequest(request: McpPendingRequest): void {
    this.emit("request", request);
    this.mainWindow?.webContents.send(IPC_CHANNELS.MCP_ACCESS_REQUEST, request);
  }

  private emitResolved(request: McpPendingRequest): void {
    this.emit("resolved", request);
    this.mainWindow?.webContents.send(IPC_CHANNELS.MCP_REQUEST_RESOLVED, request);
  }

  // ─── Helpers ─────────────────────────────────────────────────────────────

  /**
   * Validates Bearer token using timing-safe comparison.
   * Returns a synthetic agent ID derived from the token prefix (not the token itself).
   * Returns null if token is absent or invalid.
   */
  private validateBearer(req: Request): string | null {
    const authHeader = req.headers["authorization"];
    if (typeof authHeader !== "string") { return null; }

    const match = /^Bearer\s+(.+)$/.exec(authHeader);
    if (!match || !match[1]) { return null; }

    const provided = match[1];
    const providedBuf = Buffer.from(provided, "utf8");

    // Buffers must be the same length for timingSafeEqual
    if (providedBuf.length !== this.bearerTokenBuf.length) {
      // Still do a dummy comparison to prevent timing oracle
      timingSafeEqual(this.bearerTokenBuf, this.bearerTokenBuf);
      return null;
    }

    if (!timingSafeEqual(providedBuf, this.bearerTokenBuf)) {
      return null;
    }

    // Derive a stable, non-secret agent ID from the IP + user-agent
    const ip = req.socket.remoteAddress ?? "unknown";
    const ua = (req.headers["user-agent"] ?? "").slice(0, 64);
    return `agent:${ip}:${ua}`.slice(0, 128);
  }

  private countPendingForAgent(agentId: string): number {
    let count = 0;
    for (const entry of this.pendingRequests.values()) {
      if (entry.request.agentId === agentId) { count++; }
    }
    return count;
  }
}

// ─── Arg Helpers ─────────────────────────────────────────────────────────────

function extractArgs(body: unknown): Record<string, unknown> | null {
  if (typeof body !== "object" || body === null) { return null; }
  const b = body as Record<string, unknown>;
  if (typeof b["args"] !== "object" || b["args"] === null) { return null; }
  return b["args"] as Record<string, unknown>;
}

/**
 * Sanitize args for display in the UI.
 * Truncates long strings and masks fields that look like passwords/tokens.
 */
function sanitizeArgs(args: Record<string, unknown>): Record<string, unknown> {
  const SENSITIVE_KEYS = /password|token|secret|key|auth|credential/i;
  const out: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(args)) {
    if (SENSITIVE_KEYS.test(key)) {
      out[key] = "[redacted]";
    } else if (typeof value === "string" && value.length > 200) {
      out[key] = value.slice(0, 200) + "…";
    } else {
      out[key] = value;
    }
  }
  return out;
}
