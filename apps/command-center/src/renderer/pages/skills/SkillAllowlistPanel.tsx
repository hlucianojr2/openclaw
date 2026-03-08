/**
 * SkillAllowlistPanel — table of currently approved skills.
 *
 * Shows each allowlisted skill with its risk level, approval date,
 * and an option to remove it (requires elevation from the parent handler).
 */

import React from "react";
import type { AllowlistEntry } from "../../../shared/ipc-types.js";

interface Props {
  entries: AllowlistEntry[];
  onRemove: (skillId: string) => Promise<void>;
  removing: string | null;
}

const RISK_COLOR: Record<string, string> = {
  low: "var(--accent-success)",
  medium: "var(--accent-warning)",
  high: "var(--accent-danger)",
  blocked: "#dc2626",
};

export function SkillAllowlistPanel({ entries, onRemove, removing }: Props) {
  if (entries.length === 0) {
    return (
      <div style={st.empty}>
        <div style={{ fontSize: "28px", opacity: 0.3, marginBottom: "8px" }}>◈</div>
        <span>No skills on allowlist</span>
      </div>
    );
  }

  return (
    <div style={st.list}>
      {entries.map((entry) => (
        <div key={entry.skillId} style={st.row}>
          <div style={st.info}>
            <span style={st.skillName}>{entry.skillName}</span>
            <span style={st.skillId}>{entry.skillId}</span>
          </div>

          <div style={st.meta}>
            <span style={{ ...st.riskBadge, color: RISK_COLOR[entry.riskLevel] }}>
              {entry.riskLevel}
            </span>
            <span style={st.date}>
              {new Date(entry.addedAt).toLocaleDateString()}
            </span>
            <span style={st.userId}>
              {entry.addedByUserId.slice(0, 8)}
            </span>
            {entry.scanSummary && entry.scanSummary.critical === 0 && entry.scanSummary.warn === 0 && (
              <span style={st.cleanBadge}>✓ clean scan</span>
            )}
            {entry.scanSummary && entry.scanSummary.critical > 0 && (
              <span style={st.critBadge}>{entry.scanSummary.critical} critical</span>
            )}
          </div>

          <button
            style={st.removeBtn}
            disabled={removing === entry.skillId}
            onClick={() => void onRemove(entry.skillId)}
            title="Remove from allowlist"
            aria-label={`Remove ${entry.skillName} from allowlist`}
          >
            {removing === entry.skillId ? "…" : "✕"}
          </button>
        </div>
      ))}
    </div>
  );
}

const st: Record<string, React.CSSProperties> = {
  list: {
    display: "flex",
    flexDirection: "column" as React.CSSProperties["flexDirection"],
    gap: "2px",
  },
  row: {
    display: "flex",
    alignItems: "center",
    gap: "16px",
    padding: "12px 16px",
    background: "var(--surface-1)",
    borderRadius: "8px",
    transition: "background 150ms",
  },
  info: {
    display: "flex",
    flexDirection: "column" as React.CSSProperties["flexDirection"],
    gap: "2px",
    flex: 1,
    minWidth: 0,
  },
  skillName: {
    fontSize: "14px",
    fontWeight: 600,
    color: "var(--text-primary)",
  },
  skillId: {
    fontSize: "11px",
    color: "var(--text-muted)",
    fontFamily: "var(--font-mono)",
  },
  meta: {
    display: "flex",
    alignItems: "center",
    gap: "10px",
    flexShrink: 0,
  },
  riskBadge: {
    fontSize: "10px",
    fontWeight: 700,
    textTransform: "uppercase" as React.CSSProperties["textTransform"],
    letterSpacing: "0.04em",
    padding: "2px 6px",
    borderRadius: "4px",
    background: "var(--surface-2)",
  },
  date: {
    fontSize: "11px",
    color: "var(--text-tertiary)",
    whiteSpace: "nowrap" as React.CSSProperties["whiteSpace"],
  },
  userId: {
    fontSize: "11px",
    color: "var(--text-muted)",
    fontFamily: "var(--font-mono)",
  },
  cleanBadge: {
    fontSize: "10px",
    color: "var(--accent-success)",
    fontWeight: 600,
  },
  critBadge: {
    fontSize: "10px",
    color: "var(--accent-danger)",
    fontWeight: 600,
  },
  removeBtn: {
    background: "none",
    border: "1px solid var(--border-default)",
    borderRadius: "6px",
    padding: "4px 8px",
    fontSize: "12px",
    color: "var(--text-muted)",
    cursor: "pointer",
    flexShrink: 0,
    transition: "all 150ms",
  },
  empty: {
    textAlign: "center" as React.CSSProperties["textAlign"],
    padding: "48px 20px",
    color: "var(--text-tertiary)",
    fontSize: "13px",
  },
};
