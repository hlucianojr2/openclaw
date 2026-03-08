/**
 * SkillRequestCard — displays a pending SkillApprovalRequest.
 *
 * Shows scan progress, AI review, and approve/reject actions.
 * The `elevated` prop controls whether action buttons are rendered;
 * the parent is responsible for gating on session role.
 */

import React, { useState } from "react";
import type { SkillApprovalRequest, AiReviewResult } from "../../../shared/ipc-types.js";
import { SkillScanResults } from "./SkillScanResults.js";

interface Props {
  request: SkillApprovalRequest;
  /** If true, show Approve / Reject actions. */
  elevated: boolean;
  onApprove: (requestId: string) => Promise<void>;
  onReject: (requestId: string, reason: string) => Promise<void>;
  busy: boolean;
}

const RISK_COLOR: Record<string, string> = {
  low: "var(--accent-success)",
  medium: "var(--accent-warning)",
  high: "var(--accent-danger)",
  blocked: "#dc2626",
};

const AI_REC_COLOR: Record<string, string> = {
  approve: "var(--accent-success)",
  reject: "var(--accent-danger)",
  review: "var(--accent-warning)",
};

export function SkillRequestCard({ request, elevated, onApprove, onReject, busy }: Props) {
  const [showRejectInput, setShowRejectInput] = useState(false);
  const [rejectReason, setRejectReason] = useState("");

  const isAdminReview = request.approvalLevel === "admin-review";
  const hasScan = request.scanSummary !== undefined;
  const hasAi = request.aiReview !== undefined;

  const isScanning = isAdminReview && !hasScan && request.status === "pending";
  const isAiReviewing = isAdminReview && hasScan && !hasAi && request.status === "pending";
  const readyForAction = request.status === "pending" && (!isAdminReview || hasScan);

  const handleApprove = () => { void onApprove(request.id); };
  const handleRejectConfirm = () => {
    void onReject(request.id, rejectReason);
    setShowRejectInput(false);
    setRejectReason("");
  };

  return (
    <div style={st.card}>
      {/* Header */}
      <div style={st.header}>
        <div style={st.titleRow}>
          <span style={st.skillName}>{request.skillName}</span>
          <span style={{ ...st.badge, color: RISK_COLOR[request.riskLevel] }}>
            {request.riskLevel} risk
          </span>
          <span style={{ ...st.badge, color: "var(--text-tertiary)" }}>
            {request.approvalLevel === "user-ack" ? "user ack" : "admin review"}
          </span>
        </div>
        <span style={st.meta}>
          {new Date(request.requestedAt).toLocaleDateString()} · {request.requestedByUserId.slice(0, 8)}
        </span>
      </div>

      {/* Scan / AI review state */}
      {isAdminReview && (
        <div style={{ marginTop: "10px" }}>
          {isScanning && (
            <SpinnerRow label="Scanning skill source…" />
          )}
          {hasScan && (
            <SkillScanResults summary={request.scanSummary!} />
          )}
          {isAiReviewing && (
            <SpinnerRow label="Running AI review…" style={{ marginTop: "8px" }} />
          )}
          {hasAi && (
            <AiReviewBlock review={request.aiReview!} />
          )}
        </div>
      )}

      {/* Rejection reason */}
      {request.status === "rejected" && request.rejectionReason && (
        <div style={st.rejectedNote}>Rejected: {request.rejectionReason}</div>
      )}

      {/* Actions */}
      {elevated && readyForAction && request.status === "pending" && (
        <div style={st.actions}>
          {showRejectInput ? (
            <div style={st.rejectRow}>
              <input
                type="text"
                placeholder="Reason (optional)"
                value={rejectReason}
                onChange={(e) => setRejectReason(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") { handleRejectConfirm(); } }}
                style={st.rejectInput}
                autoFocus
              />
              <button style={st.dangerBtn} disabled={busy} onClick={handleRejectConfirm}>
                Confirm
              </button>
              <button style={st.ghostBtn} onClick={() => setShowRejectInput(false)}>
                Cancel
              </button>
            </div>
          ) : (
            <>
              <button style={st.successBtn} disabled={busy} onClick={handleApprove}>
                {busy ? "…" : "✓ Approve"}
              </button>
              <button style={st.dangerOutlineBtn} disabled={busy} onClick={() => setShowRejectInput(true)}>
                ✗ Reject
              </button>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function SpinnerRow({ label, style: extraStyle }: { label: string; style?: React.CSSProperties }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "12px", color: "var(--text-tertiary)", padding: "6px 0", ...extraStyle }}>
      <div className="spinner" style={{ width: "10px", height: "10px" }} />
      <span>{label}</span>
    </div>
  );
}

function AiReviewBlock({ review }: { review: AiReviewResult }) {
  return (
    <div style={st.aiBlock}>
      <div style={st.aiHeader}>
        <span style={st.aiLabel}>AI Review</span>
        <span style={{ fontWeight: 700, fontSize: "12px", textTransform: "uppercase" as React.CSSProperties["textTransform"], color: AI_REC_COLOR[review.recommendation] }}>
          {review.recommendation}
        </span>
        <span style={{ fontSize: "11px", color: "var(--text-muted)", marginLeft: "auto" }}>
          {Math.round(review.confidence * 100)}% confidence
        </span>
      </div>
      <p style={st.aiSummary}>{review.summary}</p>
      {review.concerns.length > 0 && (
        <ul style={st.concerns}>
          {review.concerns.map((c, i) => (
            <li key={i} style={{ fontSize: "12px", color: "var(--accent-warning)" }}>⚠ {c}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

const st: Record<string, React.CSSProperties> = {
  card: {
    background: "var(--surface-1)",
    border: "1px solid var(--border-subtle)",
    borderRadius: "10px",
    padding: "16px",
  },
  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: "12px",
  },
  titleRow: {
    display: "flex",
    alignItems: "center",
    gap: "8px",
    flexWrap: "wrap" as React.CSSProperties["flexWrap"],
  },
  skillName: {
    fontSize: "15px",
    fontWeight: 600,
    color: "var(--text-primary)",
  },
  badge: {
    fontSize: "10px",
    fontWeight: 600,
    textTransform: "uppercase" as React.CSSProperties["textTransform"],
    letterSpacing: "0.04em",
    padding: "2px 6px",
    borderRadius: "4px",
    background: "var(--surface-2)",
  },
  meta: {
    fontSize: "11px",
    color: "var(--text-muted)",
    whiteSpace: "nowrap" as React.CSSProperties["whiteSpace"],
    flexShrink: 0,
  },
  aiBlock: {
    marginTop: "10px",
    background: "var(--surface-2)",
    borderRadius: "8px",
    padding: "10px 12px",
  },
  aiHeader: {
    display: "flex",
    alignItems: "center",
    gap: "10px",
    marginBottom: "6px",
  },
  aiLabel: {
    fontSize: "10px",
    fontWeight: 600,
    textTransform: "uppercase" as React.CSSProperties["textTransform"],
    letterSpacing: "0.05em",
    color: "var(--text-tertiary)",
  },
  aiSummary: {
    fontSize: "13px",
    color: "var(--text-secondary)",
    lineHeight: 1.5,
    margin: 0,
  },
  concerns: {
    listStyle: "none",
    marginTop: "8px",
    display: "flex",
    flexDirection: "column" as React.CSSProperties["flexDirection"],
    gap: "3px",
  },
  rejectedNote: {
    marginTop: "10px",
    fontSize: "12px",
    color: "var(--accent-danger)",
    fontStyle: "italic" as React.CSSProperties["fontStyle"],
  },
  actions: {
    marginTop: "14px",
    display: "flex",
    gap: "8px",
    alignItems: "center",
  },
  rejectRow: {
    display: "flex",
    gap: "8px",
    alignItems: "center",
    flex: 1,
  },
  rejectInput: {
    flex: 1,
    background: "var(--surface-2)",
    border: "1px solid var(--border-default)",
    borderRadius: "6px",
    padding: "6px 10px",
    fontSize: "12px",
    color: "var(--text-primary)",
    outline: "none",
  },
  successBtn: {
    background: "var(--accent-success)",
    border: "none",
    borderRadius: "6px",
    padding: "7px 16px",
    fontSize: "12px",
    fontWeight: 600,
    color: "white",
    cursor: "pointer",
  },
  dangerBtn: {
    background: "var(--accent-danger)",
    border: "none",
    borderRadius: "6px",
    padding: "7px 14px",
    fontSize: "12px",
    fontWeight: 600,
    color: "white",
    cursor: "pointer",
  },
  dangerOutlineBtn: {
    background: "rgba(239, 68, 68, 0.12)",
    border: "1px solid var(--accent-danger)",
    borderRadius: "6px",
    padding: "6px 12px",
    fontSize: "12px",
    color: "var(--accent-danger)",
    cursor: "pointer",
  },
  ghostBtn: {
    background: "none",
    border: "1px solid var(--border-default)",
    borderRadius: "6px",
    padding: "6px 12px",
    fontSize: "12px",
    color: "var(--text-secondary)",
    cursor: "pointer",
  },
};
