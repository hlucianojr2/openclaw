/**
 * SkillScanResults — compact display of a SkillScanSummary.
 *
 * Shows a one-line count of findings by severity.
 * Expands to list individual findings on demand.
 */

import React, { useState } from "react";
import type { SkillScanSummary } from "../../../shared/ipc-types.js";

interface Props {
  summary: SkillScanSummary;
}

const SEV_COLOR = {
  critical: "var(--accent-danger)",
  warn: "var(--accent-warning)",
  info: "var(--accent-info)",
} as const;

export function SkillScanResults({ summary }: Props) {
  const [expanded, setExpanded] = useState(false);
  const hasFindings = summary.findings.length > 0;
  const isClean = summary.critical === 0 && summary.warn === 0 && summary.info === 0;

  return (
    <div style={st.wrapper}>
      <div style={st.summary}>
        <span style={st.label}>Scan</span>
        <span style={st.files}>{summary.scannedFiles} files</span>
        {isClean ? (
          <span style={{ fontSize: "12px", color: "var(--accent-success)", fontWeight: 600 }}>
            ✓ Clean
          </span>
        ) : (
          <>
            <SevBadge level="critical" count={summary.critical} />
            <SevBadge level="warn" count={summary.warn} />
            <SevBadge level="info" count={summary.info} />
          </>
        )}
        {hasFindings && (
          <button style={st.toggle} onClick={() => setExpanded((v) => !v)}>
            {expanded ? "▲ Hide" : "▼ Details"}
          </button>
        )}
      </div>

      {expanded && hasFindings && (
        <ul style={st.list}>
          {summary.findings.map((f, i) => (
            <li key={i} style={st.finding}>
              <span style={{ color: SEV_COLOR[f.severity], fontWeight: 700, fontSize: "10px", textTransform: "uppercase", minWidth: "52px" }}>
                {f.severity}
              </span>
              <span style={st.findingMeta}>{f.file}:{f.line}</span>
              <span style={st.findingMsg}>{f.message}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function SevBadge({ level, count }: { level: "critical" | "warn" | "info"; count: number }) {
  if (count === 0) { return null; }
  return (
    <span style={{ fontSize: "11px", fontWeight: 700, padding: "2px 6px", borderRadius: "4px", background: "rgba(255,255,255,0.05)", color: SEV_COLOR[level] }}>
      {count} {level}
    </span>
  );
}

const st: Record<string, React.CSSProperties> = {
  wrapper: {
    background: "var(--surface-2)",
    borderRadius: "8px",
    padding: "10px 12px",
    fontSize: "12px",
  },
  summary: {
    display: "flex",
    alignItems: "center",
    gap: "10px",
    flexWrap: "wrap",
  },
  label: {
    fontWeight: 600,
    color: "var(--text-tertiary)",
    textTransform: "uppercase" as React.CSSProperties["textTransform"],
    letterSpacing: "0.05em",
    fontSize: "10px",
  },
  files: {
    color: "var(--text-secondary)",
  },
  toggle: {
    marginLeft: "auto",
    background: "none",
    border: "none",
    color: "var(--text-tertiary)",
    cursor: "pointer",
    fontSize: "11px",
    padding: "2px 4px",
  },
  list: {
    listStyle: "none",
    marginTop: "10px",
    display: "flex",
    flexDirection: "column" as React.CSSProperties["flexDirection"],
    gap: "4px",
  },
  finding: {
    display: "flex",
    gap: "8px",
    alignItems: "baseline",
    borderTop: "1px solid var(--border-subtle)",
    paddingTop: "5px",
  },
  findingMeta: {
    color: "var(--text-muted)",
    fontFamily: "var(--font-mono)",
    fontSize: "11px",
    minWidth: "120px",
    whiteSpace: "nowrap" as React.CSSProperties["whiteSpace"],
  },
  findingMsg: {
    color: "var(--text-secondary)",
    flex: 1,
  },
};
