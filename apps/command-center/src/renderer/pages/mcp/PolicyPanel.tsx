/**
 * Policy Panel — per-category policy editor for the MCP Bridge.
 *
 * Allows operators (mcp:approve) to view policies.
 * Policy writes (changing level, domains, workspace) require
 * admin+ with elevation (mcp:policy-write).
 *
 * The panel does NOT invoke elevation itself — the IPC handler will
 * reject unelevated sessions and the error will surface in the parent.
 */

import React, { useState } from "react";
import type { McpPolicy, McpToolCategory, McpApprovalLevel } from "../../../shared/ipc-types.js";

interface PolicyPanelProps {
  policies: McpPolicy[];
  onSetPolicy: (
    category: McpToolCategory,
    updates: Partial<Pick<McpPolicy, "level" | "allowedDomains" | "workspacePath">>,
  ) => Promise<void>;
  isLoading: boolean;
}

const CATEGORY_LABELS: Record<McpToolCategory, string> = {
  filesystem: "File System",
  clipboard: "Clipboard",
  browser: "Browser",
  "system-info": "System Info",
  notifications: "Notifications",
  "app-control": "App Control",
};

const CATEGORY_DESCRIPTIONS: Record<McpToolCategory, string> = {
  filesystem: "read_file, write_file, list_dir, create_dir",
  clipboard: "read_clipboard, write_clipboard",
  browser: "open_url",
  "system-info": "get_system_info",
  notifications: "show_notification",
  "app-control": "open_app, focus_app",
};

const LEVEL_OPTIONS: { value: McpApprovalLevel; label: string; description: string }[] = [
  { value: "auto-approved", label: "Auto-Approved", description: "Always allowed without user prompt" },
  { value: "per-use", label: "Per-Use Approval", description: "User must approve each request" },
  { value: "path-constrained", label: "Path-Constrained", description: "Auto-approved only within workspace path" },
  { value: "domain-allowlist", label: "Domain Allowlist", description: "Auto-approved only for listed domains" },
  { value: "blocked", label: "Blocked", description: "Always denied, no approval pathway" },
];

/** Per-category policy editor. */
export function PolicyPanel({ policies, onSetPolicy, isLoading }: PolicyPanelProps) {
  if (policies.length === 0) {
    return (
      <div className="card" style={{ textAlign: "center", padding: "56px 32px" }}>
        <div style={{ fontSize: "40px", marginBottom: "12px", opacity: 0.3 }}>◈</div>
        <p style={{ color: "var(--text-tertiary)" }}>Loading policies...</p>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
      {policies.map((policy) => (
        <PolicyRow
          key={policy.category}
          policy={policy}
          onSetPolicy={onSetPolicy}
          isLoading={isLoading}
        />
      ))}
    </div>
  );
}

function PolicyRow({
  policy,
  onSetPolicy,
  isLoading,
}: {
  policy: McpPolicy;
  onSetPolicy: PolicyPanelProps["onSetPolicy"];
  isLoading: boolean;
}) {
  const [isEditing, setIsEditing] = useState(false);
  const [localLevel, setLocalLevel] = useState<McpApprovalLevel>(policy.level);
  const [localDomains, setLocalDomains] = useState<string>(policy.allowedDomains.join("\n"));
  const [localWorkspace, setLocalWorkspace] = useState<string>(policy.workspacePath);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  const handleSave = async () => {
    setSaving(true);
    setSaveError(null);
    try {
      const updates: Partial<Pick<McpPolicy, "level" | "allowedDomains" | "workspacePath">> = {
        level: localLevel,
      };
      if (localLevel === "domain-allowlist") {
        updates.allowedDomains = localDomains
          .split("\n")
          .map((d) => d.trim())
          .filter((d) => d.length > 0);
      }
      if (localLevel === "path-constrained") {
        updates.workspacePath = localWorkspace.trim();
      }
      await onSetPolicy(policy.category, updates);
      setIsEditing(false);
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : "Save failed");
    } finally {
      setSaving(false);
    }
  };

  const handleCancel = () => {
    setLocalLevel(policy.level);
    setLocalDomains(policy.allowedDomains.join("\n"));
    setLocalWorkspace(policy.workspacePath);
    setSaveError(null);
    setIsEditing(false);
  };

  return (
    <div className="card" style={{ padding: "16px 20px" }}>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: "12px" }}>
        <div>
          <div style={{ fontWeight: 600, fontSize: "14px", color: "var(--text-primary)" }}>
            {CATEGORY_LABELS[policy.category]}
          </div>
          <div style={{ fontSize: "11px", color: "var(--text-tertiary)", marginTop: "2px" }}>
            {CATEGORY_DESCRIPTIONS[policy.category]}
          </div>
        </div>

        {!isEditing ? (
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <LevelBadge level={policy.level} />
            <button
              onClick={() => setIsEditing(true)}
              disabled={isLoading}
              style={{
                background: "none",
                border: "1px solid var(--border-subtle)",
                borderRadius: "4px",
                color: "var(--text-secondary)",
                cursor: "pointer",
                fontSize: "11px",
                padding: "3px 10px",
              }}
            >
              Edit
            </button>
          </div>
        ) : (
          <div style={{ display: "flex", gap: "6px" }}>
            <button
              onClick={() => { void handleSave(); }}
              disabled={saving}
              style={{
                background: "rgba(129,140,248,0.15)",
                border: "1px solid rgba(129,140,248,0.3)",
                borderRadius: "4px",
                color: "var(--color-accent, #818cf8)",
                cursor: "pointer",
                fontSize: "11px",
                fontWeight: 600,
                padding: "3px 10px",
              }}
            >
              {saving ? "Saving..." : "Save"}
            </button>
            <button
              onClick={handleCancel}
              disabled={saving}
              style={{
                background: "none",
                border: "1px solid var(--border-subtle)",
                borderRadius: "4px",
                color: "var(--text-tertiary)",
                cursor: "pointer",
                fontSize: "11px",
                padding: "3px 10px",
              }}
            >
              Cancel
            </button>
          </div>
        )}
      </div>

      {isEditing && (
        <div style={{ marginTop: "14px" }}>
          {/* Level selector */}
          <div style={{ marginBottom: "10px" }}>
            <label style={{ fontSize: "11px", color: "var(--text-tertiary)", display: "block", marginBottom: "4px" }}>
              Approval Level
            </label>
            <select
              value={localLevel}
              onChange={(e) => setLocalLevel(e.target.value as McpApprovalLevel)}
              style={{
                background: "var(--bg-secondary, #13131a)",
                border: "1px solid var(--border-subtle)",
                borderRadius: "4px",
                color: "var(--text-primary)",
                fontSize: "12px",
                padding: "4px 8px",
                width: "100%",
                maxWidth: "280px",
              }}
            >
              {LEVEL_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label} — {opt.description}
                </option>
              ))}
            </select>
          </div>

          {/* Domain allowlist (when applicable) */}
          {localLevel === "domain-allowlist" && (
            <div style={{ marginBottom: "10px" }}>
              <label style={{ fontSize: "11px", color: "var(--text-tertiary)", display: "block", marginBottom: "4px" }}>
                Allowed Domains (one per line)
              </label>
              <textarea
                value={localDomains}
                onChange={(e) => setLocalDomains(e.target.value)}
                placeholder="example.com&#10;api.example.com"
                rows={4}
                style={{
                  background: "var(--bg-secondary, #13131a)",
                  border: "1px solid var(--border-subtle)",
                  borderRadius: "4px",
                  color: "var(--text-primary)",
                  fontSize: "12px",
                  fontFamily: "monospace",
                  padding: "6px 8px",
                  width: "100%",
                  maxWidth: "400px",
                  resize: "vertical",
                }}
              />
            </div>
          )}

          {/* Workspace path (when applicable) */}
          {localLevel === "path-constrained" && (
            <div style={{ marginBottom: "10px" }}>
              <label style={{ fontSize: "11px", color: "var(--text-tertiary)", display: "block", marginBottom: "4px" }}>
                Workspace Path (absolute path)
              </label>
              <input
                type="text"
                value={localWorkspace}
                onChange={(e) => setLocalWorkspace(e.target.value)}
                placeholder="/workspace"
                style={{
                  background: "var(--bg-secondary, #13131a)",
                  border: "1px solid var(--border-subtle)",
                  borderRadius: "4px",
                  color: "var(--text-primary)",
                  fontSize: "12px",
                  fontFamily: "monospace",
                  padding: "4px 8px",
                  width: "100%",
                  maxWidth: "400px",
                }}
              />
            </div>
          )}

          {saveError && (
            <div style={{
              color: "var(--color-danger, #ef4444)",
              fontSize: "11px",
              marginTop: "4px",
            }}>
              {saveError}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function LevelBadge({ level }: { level: McpApprovalLevel }) {
  const styles: Record<McpApprovalLevel, { bg: string; color: string; label: string }> = {
    "auto-approved": { bg: "rgba(34,197,94,0.15)", color: "var(--color-success, #22c55e)", label: "Auto" },
    "per-use": { bg: "rgba(245,158,11,0.15)", color: "var(--color-warning, #f59e0b)", label: "Per-Use" },
    "path-constrained": { bg: "rgba(129,140,248,0.15)", color: "var(--color-accent, #818cf8)", label: "Path" },
    "domain-allowlist": { bg: "rgba(129,140,248,0.15)", color: "var(--color-accent, #818cf8)", label: "Domains" },
    "blocked": { bg: "rgba(239,68,68,0.1)", color: "var(--color-danger, #ef4444)", label: "Blocked" },
  };
  const s = styles[level];
  return (
    <span style={{
      background: s.bg,
      color: s.color,
      borderRadius: "4px",
      fontSize: "11px",
      fontWeight: 600,
      padding: "2px 8px",
    }}>
      {s.label}
    </span>
  );
}
