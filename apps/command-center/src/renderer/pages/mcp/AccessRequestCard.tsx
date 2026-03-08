/**
 * Access Request Card — displays a pending MCP tool access request
 * with approve/deny controls.
 *
 * Shows tool name, category, agent ID, args preview (pre-sanitized by server),
 * and time remaining before expiry.
 */

import React, { useState, useEffect } from "react";
import type { McpAccessRequest, McpToolCategory } from "../../../shared/ipc-types.js";

const APPROVAL_TIMEOUT_MS = 60_000;

interface AccessRequestCardProps {
  request: McpAccessRequest;
  onApprove: (id: string) => Promise<void>;
  onDeny: (id: string) => Promise<void>;
  disabled?: boolean;
}

/** Category display labels — no Docker/internal terminology. */
const CATEGORY_LABELS: Record<McpToolCategory, string> = {
  filesystem: "File System",
  clipboard: "Clipboard",
  browser: "Browser",
  "system-info": "System Info",
  notifications: "Notifications",
  "app-control": "App Control",
};

const CATEGORY_ICONS: Record<McpToolCategory, string> = {
  filesystem: "◉",
  clipboard: "◎",
  browser: "◈",
  "system-info": "☰",
  notifications: "◆",
  "app-control": "⬡",
};

/** Single pending tool access request card with approve/deny. */
export function AccessRequestCard({ request, onApprove, onDeny, disabled }: AccessRequestCardProps) {
  const [timeLeft, setTimeLeft] = useState<number>(() => {
    const elapsed = Date.now() - request.receivedAt;
    return Math.max(0, APPROVAL_TIMEOUT_MS - elapsed);
  });
  const [acting, setActing] = useState(false);

  // Countdown timer
  useEffect(() => {
    if (timeLeft <= 0) { return; }
    const interval = setInterval(() => {
      const elapsed = Date.now() - request.receivedAt;
      const remaining = Math.max(0, APPROVAL_TIMEOUT_MS - elapsed);
      setTimeLeft(remaining);
    }, 500);
    return () => clearInterval(interval);
  }, [request.receivedAt, timeLeft]);

  const handleApprove = async () => {
    setActing(true);
    try {
      await onApprove(request.id);
    } finally {
      setActing(false);
    }
  };

  const handleDeny = async () => {
    setActing(true);
    try {
      await onDeny(request.id);
    } finally {
      setActing(false);
    }
  };

  const isExpired = timeLeft <= 0 || request.state === "expired";
  const isResolved = request.state !== "pending" && request.state !== "auto";
  const isDisabled = disabled || acting || isExpired || isResolved;

  const secondsLeft = Math.ceil(timeLeft / 1000);
  const urgencyColor = timeLeft < 10_000
    ? "var(--color-danger, #ef4444)"
    : timeLeft < 30_000
    ? "var(--color-warning, #f59e0b)"
    : "var(--text-tertiary)";

  return (
    <div className="card" style={{
      padding: "16px 20px",
      borderLeft: `3px solid ${isExpired ? "var(--border-subtle)" : "var(--color-warning, #f59e0b)"}`,
      opacity: isExpired ? 0.6 : 1,
    }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: "12px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <span style={{ fontSize: "18px", opacity: 0.8 }}>
            {CATEGORY_ICONS[request.category]}
          </span>
          <div>
            <div style={{ fontWeight: 600, fontSize: "14px", color: "var(--text-primary)" }}>
              {request.toolName}
            </div>
            <div style={{ fontSize: "11px", color: "var(--text-tertiary)", marginTop: "2px" }}>
              {CATEGORY_LABELS[request.category]}
            </div>
          </div>
        </div>

        {/* Timer */}
        {!isResolved && (
          <div style={{ textAlign: "right", fontSize: "11px", color: urgencyColor, fontWeight: 600 }}>
            {isExpired ? "Expired" : `${secondsLeft}s`}
          </div>
        )}

        {/* Resolved state badge */}
        {isResolved && (
          <div style={{
            fontSize: "11px",
            padding: "2px 8px",
            borderRadius: "4px",
            background: request.state === "approved"
              ? "rgba(34,197,94,0.15)"
              : "rgba(239,68,68,0.1)",
            color: request.state === "approved"
              ? "var(--color-success, #22c55e)"
              : "var(--color-danger, #ef4444)",
            fontWeight: 600,
          }}>
            {request.state}
          </div>
        )}
      </div>

      {/* Agent ID */}
      <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "8px" }}>
        Agent: <code style={{ fontSize: "11px" }}>{request.agentId.slice(0, 40)}</code>
      </div>

      {/* Args preview */}
      {Object.keys(request.argsPreview).length > 0 && (
        <div style={{
          background: "rgba(0,0,0,0.2)",
          borderRadius: "4px",
          padding: "8px 10px",
          marginTop: "10px",
          fontFamily: "monospace",
          fontSize: "11px",
          color: "var(--text-secondary)",
          maxHeight: "80px",
          overflow: "auto",
        }}>
          {Object.entries(request.argsPreview).map(([k, v]) => (
            <div key={k}>
              <span style={{ color: "var(--text-tertiary)" }}>{k}: </span>
              <span>{typeof v === "string" ? v : JSON.stringify(v)}</span>
            </div>
          ))}
        </div>
      )}

      {/* Actions */}
      {request.state === "pending" && !isExpired && (
        <div style={{ display: "flex", gap: "8px", marginTop: "14px" }}>
          <button
            onClick={() => { void handleApprove(); }}
            disabled={isDisabled}
            style={{
              background: "rgba(34,197,94,0.15)",
              border: "1px solid rgba(34,197,94,0.3)",
              color: "var(--color-success, #22c55e)",
              borderRadius: "5px",
              padding: "6px 16px",
              fontSize: "12px",
              fontWeight: 600,
              cursor: isDisabled ? "not-allowed" : "pointer",
              opacity: isDisabled ? 0.5 : 1,
            }}
          >
            {acting ? "..." : "Approve"}
          </button>
          <button
            onClick={() => { void handleDeny(); }}
            disabled={isDisabled}
            style={{
              background: "rgba(239,68,68,0.1)",
              border: "1px solid rgba(239,68,68,0.2)",
              color: "var(--color-danger, #ef4444)",
              borderRadius: "5px",
              padding: "6px 16px",
              fontSize: "12px",
              fontWeight: 600,
              cursor: isDisabled ? "not-allowed" : "pointer",
              opacity: isDisabled ? 0.5 : 1,
            }}
          >
            {acting ? "..." : "Deny"}
          </button>
        </div>
      )}
    </div>
  );
}
