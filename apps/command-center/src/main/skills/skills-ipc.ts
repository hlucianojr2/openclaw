/**
 * Skills IPC Handlers — registers all occc:skills:* governance channels.
 *
 * Authorization:
 *   - Read operations  (list, get): requireSkillsRead — any valid session
 *   - Write operations (approve, reject, remove): requireSkillsWrite — elevated session
 */

import { ipcMain } from "electron";
import type { SessionManager } from "../auth/session-manager.js";
import type { AuthSession } from "../../shared/ipc-types.js";
import { IPC_CHANNELS } from "../../shared/ipc-types.js";
import { SkillGovernance } from "./skill-governance.js";

// ─── Auth Guards ──────────────────────────────────────────────────────────────

function requireSkillsRead(sessions: SessionManager, token: unknown): AuthSession {
  if (typeof token !== "string") { throw new Error("Unauthorized"); }
  const session = sessions.resolve(token);
  if (!session) { throw new Error("Unauthorized"); }
  return session;
}

function requireSkillsWrite(sessions: SessionManager, token: unknown): AuthSession {
  if (typeof token !== "string") { throw new Error("Unauthorized"); }
  const session = sessions.resolve(token);
  if (!session) { throw new Error("Unauthorized"); }
  if (!session.elevated) { throw new Error("Elevated session required"); }
  return session;
}

// ─── Registration ─────────────────────────────────────────────────────────────

export function registerSkillsIpcHandlers(
  sessions: SessionManager,
  governance: SkillGovernance,
): void {
  // Request skill installation
  ipcMain.handle(IPC_CHANNELS.SKILLS_REQUEST_INSTALL, async (_event, token: unknown, skillId: unknown) => {
    const session = requireSkillsRead(sessions, token);
    if (typeof skillId !== "string") {
      return { outcome: "rejected", skillId: "", message: "Invalid skill ID" };
    }
    return governance.requestInstall(skillId, session.userId);
  });

  // Get allowlist
  ipcMain.handle(IPC_CHANNELS.SKILLS_GET_ALLOWLIST, async (_event, token: unknown) => {
    requireSkillsRead(sessions, token);
    return governance.getAllowlist();
  });

  // Get all pending requests
  ipcMain.handle(IPC_CHANNELS.SKILLS_GET_PENDING, async (_event, token: unknown) => {
    requireSkillsRead(sessions, token);
    return governance.getPendingRequests();
  });

  // Get a single request by ID
  ipcMain.handle(IPC_CHANNELS.SKILLS_GET_REQUEST, async (_event, token: unknown, requestId: unknown) => {
    requireSkillsRead(sessions, token);
    if (typeof requestId !== "string") { return null; }
    return governance.getRequest(requestId);
  });

  // Approve a pending request (elevation required)
  ipcMain.handle(IPC_CHANNELS.SKILLS_APPROVE, async (_event, token: unknown, requestId: unknown) => {
    const session = requireSkillsWrite(sessions, token);
    if (typeof requestId !== "string") { return { ok: false, reason: "Invalid request ID" }; }
    return governance.approve(requestId, session.userId);
  });

  // Reject a pending request (elevation required)
  ipcMain.handle(IPC_CHANNELS.SKILLS_REJECT, async (_event, token: unknown, requestId: unknown, reason: unknown) => {
    const session = requireSkillsWrite(sessions, token);
    if (typeof requestId !== "string") { return { ok: false, reason: "Invalid request ID" }; }
    return governance.reject(
      requestId,
      session.userId,
      typeof reason === "string" ? reason : undefined,
    );
  });

  // Remove a skill from the allowlist (elevation required)
  ipcMain.handle(IPC_CHANNELS.SKILLS_REMOVE_ALLOWLIST, async (_event, token: unknown, skillId: unknown) => {
    requireSkillsWrite(sessions, token);
    if (typeof skillId !== "string") { return { ok: false, reason: "Invalid skill ID" }; }
    return governance.removeFromAllowlist(skillId);
  });
}
