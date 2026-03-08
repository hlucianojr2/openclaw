/**
 * Audit Log Panel — scrollable table of MCP tool call outcomes.
 *
 * Read-only view of the MCP Bridge audit log.
 * Shows tool name, category, agent ID, outcome, and timestamp.
 * Provides a refresh button and basic outcome filtering.
 *
 * Tool args and result data are NEVER included in audit entries —
 * the server strips them before logging.
 */

import React, { useState } from "react";
import type { McpAuditEntry, McpOutcome, McpToolCategory } from "../../../shared/ipc-types.js";

interface AuditLogPanelProps {
  entries: McpAuditEntry[];
  onRefresh: () => Promise<void>;
}

const OUTCOME_COLORS: Record<McpOutcome, string> = {
  approved: "var(--color-success, #22c55e)",
  denied: "var(--color-danger, #ef4444)",
  blocked: "rgba(239,68,68,0.7)",
  expired: "var(--color-warning, #f59e0b)",
  error: "rgba(239,68,68,0.9)",
};

const CATEGORY_LABELS: Record<McpToolCategory, string> = {
  filesystem: "File System",
  clipboard: "Clipboard",
  browser: "Browser",
  "system-info": "System Info",
  notifications: "Notifications",
  "app-control": "App Control",
};

const OUTCOME_OPTIONS: (McpOutcome | "all")[] = [
  "all", "approved", "denied", "blocked", "expired", "error",
];

/** Scrollable audit log table with filter controls. */
export function AuditLogPanel({ entries, onRefresh }: AuditLogPanelProps) {
  const [filter, setFilter] = useState<McpOutcome | "all">("all");
  const [refreshing, setRefreshing] = useState(false);

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await onRefresh();
    } finally {
      setRefreshing(false);
    }
  };

  const filtered = filter === "all"
    ? entries
    : entries.filter((e) => e.outcome === filter);

  return (
    <div>
      {/* Controls */}
      <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "16px" }}>
        <div style={{ display: "flex", gap: "4px" }}>
          {OUTCOME_OPTIONS.map((opt) => (
            <button
              key={opt}
              onClick={() => setFilter(opt)}
              style={{
                background: filter === opt ? "rgba(129,140,248,0.2)" : "none",
                border: `1px solid ${filter === opt ? "rgba(129,140,248,0.4)" : "var(--border-subtle)"}`,
                borderRadius: "4px",
                color: filter === opt ? "var(--color-accent, #818cf8)" : "var(--text-tertiary)",
                cursor: "pointer",
                fontSize: "11px",
                fontWeight: filter === opt ? 600 : 400,
                padding: "3px 9px",
              }}
            >
              {opt === "all" ? "All" : capitalize(opt)}
            </button>
          ))}
        </div>

        <button
          onClick={() => { void handleRefresh(); }}
          disabled={refreshing}
          style={{
            background: "none",
            border: "1px solid var(--border-subtle)",
            borderRadius: "4px",
            color: "var(--text-tertiary)",
            cursor: "pointer",
            fontSize: "11px",
            padding: "3px 10px",
            marginLeft: "auto",
          }}
        >
          {refreshing ? "..." : "Refresh"}
        </button>
      </div>

      {filtered.length === 0 ? (
        <div className="card" style={{ textAlign: "center", padding: "40px 32px" }}>
          <p style={{ color: "var(--text-tertiary)", fontSize: "13px" }}>
            {entries.length === 0
              ? "No audit log entries yet. Tool calls will appear here as agents make requests."
              : `No "${filter}" entries.`}
          </p>
        </div>
      ) : (
        <div style={{
          borderRadius: "6px",
          border: "1px solid var(--border-subtle)",
          overflow: "hidden",
          maxHeight: "480px",
          overflowY: "auto",
        }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
            <thead>
              <tr style={{ background: "rgba(0,0,0,0.2)", borderBottom: "1px solid var(--border-subtle)" }}>
                <th style={thStyle}>Time</th>
                <th style={thStyle}>Tool</th>
                <th style={thStyle}>Category</th>
                <th style={thStyle}>Agent</th>
                <th style={thStyle}>Outcome</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((entry) => (
                <tr
                  key={entry.id}
                  style={{ borderBottom: "1px solid var(--border-subtle)" }}
                >
                  <td style={tdStyle}>
                    <span title={entry.timestamp} style={{ fontFamily: "monospace" }}>
                      {formatTime(entry.timestamp)}
                    </span>
                  </td>
                  <td style={{ ...tdStyle, fontFamily: "monospace", fontWeight: 500 }}>
                    {entry.toolName}
                  </td>
                  <td style={tdStyle}>
                    {CATEGORY_LABELS[entry.category]}
                  </td>
                  <td style={{ ...tdStyle, fontFamily: "monospace" }}>
                    {entry.agentId.slice(0, 24)}
                    {entry.agentId.length > 24 ? "..." : ""}
                  </td>
                  <td style={tdStyle}>
                    <span style={{
                      color: OUTCOME_COLORS[entry.outcome],
                      fontWeight: 600,
                    }}>
                      {capitalize(entry.outcome)}
                    </span>
                    {entry.errorMessage && (
                      <div style={{ fontSize: "10px", color: "var(--text-muted)", marginTop: "2px" }}>
                        {entry.errorMessage.slice(0, 60)}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "8px" }}>
        Showing {filtered.length} of {entries.length} entries (last 100 loaded)
      </div>
    </div>
  );
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const thStyle: React.CSSProperties = {
  padding: "8px 12px",
  textAlign: "left",
  fontWeight: 600,
  fontSize: "11px",
  color: "var(--text-tertiary)",
  whiteSpace: "nowrap",
};

const tdStyle: React.CSSProperties = {
  padding: "8px 12px",
  color: "var(--text-secondary)",
  verticalAlign: "top",
};

function capitalize(str: string): string {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

function formatTime(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return iso;
  }
}
