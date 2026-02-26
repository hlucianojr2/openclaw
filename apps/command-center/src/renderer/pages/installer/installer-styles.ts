/**
 * Shared CSSProperties constants for installer wizard step components.
 * Import from here — do not duplicate these in individual step files.
 */
import type React from "react";

/** Per-step layout: container, heading, desc, actions, alert box. */
export const step: Record<string, React.CSSProperties> = {
  container: { maxWidth: "560px", margin: "0 auto", paddingTop: "8px" },
  heading: { fontSize: "20px", fontWeight: 700, color: "var(--text-primary)", margin: "0 0 8px" },
  desc: { fontSize: "13px", color: "var(--text-secondary)", margin: "0", lineHeight: 1.6 },
  center: { display: "flex", flexDirection: "column", alignItems: "center", padding: "40px 0" },
  actions: { display: "flex", gap: "10px", justifyContent: "flex-end", marginTop: "24px" },
  alertBox: {
    background: "rgba(239,68,68,0.08)",
    border: "1px solid rgba(239,68,68,0.3)",
    borderRadius: "10px",
    padding: "14px 16px",
    fontSize: "13px",
    color: "var(--text-secondary)",
  },
};

export const labelStyle: React.CSSProperties = {
  display: "block",
  fontSize: "12px",
  fontWeight: 600,
  color: "var(--text-tertiary)",
  textTransform: "uppercase",
  letterSpacing: "0.04em",
  marginBottom: "6px",
};

export const inputStyle: React.CSSProperties = {
  width: "100%",
  background: "rgba(30,30,42,0.8)",
  border: "1px solid rgba(255,255,255,0.1)",
  borderRadius: "10px",
  padding: "10px 14px",
  fontSize: "14px",
  color: "var(--text-primary)",
  outline: "none",
  fontFamily: "inherit",
  boxSizing: "border-box",
};

export const btnPrimary: React.CSSProperties = {
  background: "linear-gradient(135deg, #6366f1, #4f46e5)",
  border: "none",
  borderRadius: "10px",
  padding: "10px 20px",
  fontSize: "13px",
  fontWeight: 600,
  color: "white",
  cursor: "pointer",
  display: "flex",
  alignItems: "center",
  gap: "8px",
};

export const btnSecondary: React.CSSProperties = {
  background: "var(--surface-1)",
  border: "1px solid var(--border-default)",
  borderRadius: "10px",
  padding: "10px 20px",
  fontSize: "13px",
  color: "var(--text-secondary)",
  cursor: "pointer",
};

export const btnDisabled: React.CSSProperties = {
  ...btnPrimary,
  opacity: 0.5,
  cursor: "not-allowed",
};
