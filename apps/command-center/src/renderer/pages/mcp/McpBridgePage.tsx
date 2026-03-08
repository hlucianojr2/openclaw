/**
 * MCP Bridge Page — 3-tab view: Requests / Policy / Audit.
 *
 * Requires session (mcp:view permission).
 * Policy writes require elevated session (mcp:policy-write).
 */

import React, { useState, useEffect, useCallback } from "react";
import { useAuth } from "../../App.js";
import { AccessRequestCard } from "./AccessRequestCard.js";
import { PolicyPanel } from "./PolicyPanel.js";
import { AuditLogPanel } from "./AuditLogPanel.js";
import type {
  McpAccessRequest,
  McpBridgeStatus,
  McpPolicy,
  McpAuditEntry,
  McpToolCategory,
  OcccBridge,
} from "../../../shared/ipc-types.js";

const occc = (window as unknown as { occc: OcccBridge }).occc;

type Tab = "requests" | "policy" | "audit";

interface McpBridgePageProps {
  pendingCount: number;
}

/** MCP Bridge management page with 3 tabs. */
export function McpBridgePage({ pendingCount }: McpBridgePageProps) {
  const { token } = useAuth();
  const [activeTab, setActiveTab] = useState<Tab>("requests");
  const [status, setStatus] = useState<McpBridgeStatus | null>(null);
  const [pending, setPending] = useState<McpAccessRequest[]>([]);
  const [policies, setPolicies] = useState<McpPolicy[]>([]);
  const [auditLog, setAuditLog] = useState<McpAuditEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  // ─── Data Loading ────────────────────────────────────────────────────────

  const loadStatus = useCallback(async () => {
    if (!token) { return; }
    try {
      const s = await occc.mcpGetStatus(token);
      setStatus(s);
    } catch {
      // Status load failure is non-fatal
    }
  }, [token]);

  const loadPending = useCallback(async () => {
    if (!token) { return; }
    try {
      const requests = await occc.mcpGetPending(token);
      setPending(requests);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load pending requests");
    }
  }, [token]);

  const loadPolicies = useCallback(async () => {
    if (!token) { return; }
    try {
      const p = await occc.mcpGetPolicies(token);
      setPolicies(p);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load policies");
    }
  }, [token]);

  const loadAuditLog = useCallback(async () => {
    if (!token) { return; }
    try {
      const entries = await occc.mcpGetAuditLog(token, 100);
      setAuditLog(entries);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load audit log");
    }
  }, [token]);

  // Initial load and tab-driven refresh
  useEffect(() => {
    void loadStatus();
    if (activeTab === "requests") { void loadPending(); }
    if (activeTab === "policy") { void loadPolicies(); }
    if (activeTab === "audit") { void loadAuditLog(); }
  }, [activeTab, loadStatus, loadPending, loadPolicies, loadAuditLog]);

  // Poll pending requests and status every 5 seconds when on requests tab
  useEffect(() => {
    if (activeTab !== "requests") { return; }
    const interval = setInterval(() => {
      void loadPending();
      void loadStatus();
    }, 5_000);
    return () => clearInterval(interval);
  }, [activeTab, loadPending, loadStatus]);

  // Listen for real-time push events from the MCP Bridge
  useEffect(() => {
    const handleNew = () => {
      void loadPending();
      void loadStatus();
    };
    const handleResolved = () => {
      void loadPending();
      void loadStatus();
      if (activeTab === "audit") { void loadAuditLog(); }
    };
    occc.on("occc:mcp:access-request", handleNew);
    occc.on("occc:mcp:request-resolved", handleResolved);
    return () => {
      occc.off("occc:mcp:access-request", handleNew);
      occc.off("occc:mcp:request-resolved", handleResolved);
    };
  }, [activeTab, loadPending, loadStatus, loadAuditLog]);

  // ─── Actions ─────────────────────────────────────────────────────────────

  const handleApprove = useCallback(async (requestId: string) => {
    if (!token) { return; }
    setIsLoading(true);
    setError(null);
    try {
      await occc.mcpApprove(token, requestId);
      await loadPending();
      await loadStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Approval failed");
    } finally {
      setIsLoading(false);
    }
  }, [token, loadPending, loadStatus]);

  const handleDeny = useCallback(async (requestId: string) => {
    if (!token) { return; }
    setIsLoading(true);
    setError(null);
    try {
      await occc.mcpDeny(token, requestId);
      await loadPending();
      await loadStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Denial failed");
    } finally {
      setIsLoading(false);
    }
  }, [token, loadPending, loadStatus]);

  const handleSetPolicy = useCallback(async (
    category: McpToolCategory,
    updates: Partial<Pick<McpPolicy, "level" | "allowedDomains" | "workspacePath">>,
  ) => {
    if (!token) { return; }
    setIsLoading(true);
    setError(null);
    try {
      const updated = await occc.mcpSetPolicy(token, category, updates);
      setPolicies((prev) => prev.map((p) => (p.category === category ? updated : p)));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Policy update failed");
    } finally {
      setIsLoading(false);
    }
  }, [token]);

  // ─── Render ──────────────────────────────────────────────────────────────

  return (
    <div>
      <div className="page-header">
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <h1>MCP Bridge</h1>
          {status && (
            <span style={{
              fontSize: "11px",
              padding: "2px 8px",
              borderRadius: "4px",
              background: status.running ? "rgba(34,197,94,0.15)" : "rgba(239,68,68,0.15)",
              color: status.running ? "var(--color-success, #22c55e)" : "var(--color-danger, #ef4444)",
              fontWeight: 600,
            }}>
              {status.running ? `Running :${status.port}` : "Stopped"}
            </span>
          )}
        </div>
        <p>Tool access control for agent workspaces. Approve, deny, or configure tool policies.</p>
      </div>

      {/* Stats bar */}
      {status && (
        <div style={{ display: "flex", gap: "16px", marginBottom: "20px" }}>
          <StatBadge label="Pending" value={status.pendingCount} color="warning" />
          <StatBadge label="Approved today" value={status.todayApproved} color="success" />
          <StatBadge label="Denied today" value={status.todayDenied} color="danger" />
          <StatBadge label="Blocked today" value={status.todayBlocked} color="muted" />
        </div>
      )}

      {/* Error banner */}
      {error && (
        <div style={{
          background: "rgba(239,68,68,0.1)",
          border: "1px solid rgba(239,68,68,0.3)",
          borderRadius: "6px",
          padding: "10px 14px",
          color: "var(--color-danger, #ef4444)",
          fontSize: "13px",
          marginBottom: "16px",
        }}>
          {error}
        </div>
      )}

      {/* Tab bar */}
      <div style={{ display: "flex", gap: "4px", borderBottom: "1px solid var(--border-subtle)", marginBottom: "20px" }}>
        <TabButton id="requests" active={activeTab} onClick={setActiveTab} badge={pendingCount > 0 ? pendingCount : undefined}>
          Requests
        </TabButton>
        <TabButton id="policy" active={activeTab} onClick={setActiveTab}>
          Policy
        </TabButton>
        <TabButton id="audit" active={activeTab} onClick={setActiveTab}>
          Audit Log
        </TabButton>
      </div>

      {/* Tab content */}
      {activeTab === "requests" && (
        <RequestsTab
          requests={pending}
          onApprove={handleApprove}
          onDeny={handleDeny}
          isLoading={isLoading}
        />
      )}
      {activeTab === "policy" && (
        <PolicyPanel
          policies={policies}
          onSetPolicy={handleSetPolicy}
          isLoading={isLoading}
        />
      )}
      {activeTab === "audit" && (
        <AuditLogPanel entries={auditLog} onRefresh={loadAuditLog} />
      )}
    </div>
  );
}

// ─── Sub-components ──────────────────────────────────────────────────────────

function RequestsTab({
  requests,
  onApprove,
  onDeny,
  isLoading,
}: {
  requests: McpAccessRequest[];
  onApprove: (id: string) => Promise<void>;
  onDeny: (id: string) => Promise<void>;
  isLoading: boolean;
}) {
  if (requests.length === 0) {
    return (
      <div className="card" style={{ textAlign: "center", padding: "56px 32px" }}>
        <div style={{ fontSize: "40px", marginBottom: "12px", opacity: 0.3 }}>⇌</div>
        <p style={{ color: "var(--text-tertiary)" }}>
          No pending tool access requests. Agent workspaces will appear here when they request tool access.
        </p>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
      {requests.map((req) => (
        <AccessRequestCard
          key={req.id}
          request={req}
          onApprove={onApprove}
          onDeny={onDeny}
          disabled={isLoading}
        />
      ))}
    </div>
  );
}

function TabButton({
  id,
  active,
  onClick,
  children,
  badge,
}: {
  id: Tab;
  active: Tab;
  onClick: (id: Tab) => void;
  children: React.ReactNode;
  badge?: number;
}) {
  const isActive = id === active;
  return (
    <button
      onClick={() => onClick(id)}
      style={{
        background: "none",
        border: "none",
        borderBottom: isActive ? "2px solid var(--color-accent, #818cf8)" : "2px solid transparent",
        color: isActive ? "var(--text-primary)" : "var(--text-tertiary)",
        cursor: "pointer",
        fontSize: "13px",
        fontWeight: isActive ? 600 : 400,
        padding: "8px 16px",
        marginBottom: "-1px",
        display: "flex",
        alignItems: "center",
        gap: "6px",
      }}
    >
      {children}
      {badge !== undefined && (
        <span style={{
          background: "var(--color-warning, #f59e0b)",
          color: "#000",
          borderRadius: "9px",
          fontSize: "10px",
          fontWeight: 700,
          padding: "1px 5px",
        }}>
          {badge}
        </span>
      )}
    </button>
  );
}

function StatBadge({ label, value, color }: { label: string; value: number; color: "warning" | "success" | "danger" | "muted" }) {
  const colors: Record<string, string> = {
    warning: "rgba(245,158,11,0.15)",
    success: "rgba(34,197,94,0.15)",
    danger: "rgba(239,68,68,0.15)",
    muted: "rgba(148,163,184,0.1)",
  };
  return (
    <div style={{
      background: colors[color],
      borderRadius: "6px",
      padding: "8px 14px",
      fontSize: "12px",
    }}>
      <div style={{ fontWeight: 700, fontSize: "20px", color: "var(--text-primary)" }}>{value}</div>
      <div style={{ color: "var(--text-tertiary)" }}>{label}</div>
    </div>
  );
}
