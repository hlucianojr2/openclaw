/**
 * SkillGovernancePage — Phase 5 Skill Governance UI.
 *
 * Three tabs:
 *   Pending Reviews — pending SkillApprovalRequests (polled every 3s)
 *   Allowlist       — currently approved skills with remove action
 *   Skill Catalog   — available skills to request installation
 *
 * Approve / reject / remove all require elevation (IPC-enforced).
 */

import React, { useState, useEffect, useCallback } from "react";
import type { OcccBridge, SkillApprovalRequest, AllowlistEntry, SkillCatalogEntry } from "../../../shared/ipc-types.js";
import { useAuth } from "../../App.js";
import { SkillRequestCard } from "./SkillRequestCard.js";
import { SkillAllowlistPanel } from "./SkillAllowlistPanel.js";

const occc = (window as unknown as { occc: OcccBridge }).occc;

type Tab = "pending" | "allowlist" | "catalog";

const RISK_COLOR: Record<string, string> = {
  low: "var(--accent-success)",
  medium: "var(--accent-warning)",
  high: "var(--accent-danger)",
  blocked: "#dc2626",
};

const APPROVAL_LEVEL_LABEL: Record<string, string> = {
  "auto-approved": "Auto",
  "user-ack": "Ack",
  "admin-review": "Admin",
  blocked: "Blocked",
};

const APPROVAL_LEVEL_COLOR: Record<string, string> = {
  "auto-approved": "var(--accent-success)",
  "user-ack": "var(--accent-warning)",
  "admin-review": "var(--accent-danger)",
  blocked: "#dc2626",
};

export function SkillGovernancePage() {
  const { token, session, requireElevation } = useAuth();
  const [tab, setTab] = useState<Tab>("pending");
  const [pending, setPending] = useState<SkillApprovalRequest[]>([]);
  const [allowlist, setAllowlist] = useState<AllowlistEntry[]>([]);
  const [catalog, setCatalog] = useState<SkillCatalogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [removing, setRemoving] = useState<string | null>(null);
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null);
  const [catalogSearch, setCatalogSearch] = useState("");

  const showToast = useCallback((msg: string, ok: boolean) => {
    setToast({ msg, ok });
    setTimeout(() => setToast(null), 3500);
  }, []);

  const refresh = useCallback(async () => {
    if (!token) { return; }
    try {
      const [p, a, c] = await Promise.all([
        occc.skillGetPending(token),
        occc.skillGetAllowlist(token),
        occc.installGetSkillCatalog(),
      ]);
      setPending(p);
      setAllowlist(a);
      setCatalog(c);
    } catch (err) {
      console.error("Skill governance refresh failed:", err);
    } finally {
      setLoading(false);
    }
  }, [token]);

  // Initial load + poll for scan/AI progress
  useEffect(() => {
    void refresh();
    const id = setInterval(() => { void refresh(); }, 3000);
    return () => clearInterval(id);
  }, [refresh]);

  const handleApprove = useCallback(async (requestId: string) => {
    if (!token) { return; }
    const elevated = await requireElevation("Approve skill");
    if (!elevated) { return; }
    setBusy(requestId);
    try {
      const result = await occc.skillApprove(token, requestId);
      if (result.ok) {
        showToast("Skill approved and added to allowlist.", true);
        void refresh();
      } else {
        showToast(result.reason ?? "Approval failed.", false);
      }
    } catch {
      showToast("Approval failed.", false);
    } finally {
      setBusy(null);
    }
  }, [token, requireElevation, refresh, showToast]);

  const handleReject = useCallback(async (requestId: string, reason: string) => {
    if (!token) { return; }
    const elevated = await requireElevation("Reject skill");
    if (!elevated) { return; }
    setBusy(requestId);
    try {
      const result = await occc.skillReject(token, requestId, reason || undefined);
      if (result.ok) {
        showToast("Skill request rejected.", true);
        void refresh();
      } else {
        showToast(result.reason ?? "Rejection failed.", false);
      }
    } catch {
      showToast("Rejection failed.", false);
    } finally {
      setBusy(null);
    }
  }, [token, requireElevation, refresh, showToast]);

  const handleRemove = useCallback(async (skillId: string) => {
    if (!token) { return; }
    const elevated = await requireElevation("Remove skill from allowlist");
    if (!elevated) { return; }
    setRemoving(skillId);
    try {
      const result = await occc.skillRemoveAllowlist(token, skillId);
      if (result.ok) {
        showToast("Skill removed from allowlist.", true);
        void refresh();
      } else {
        showToast(result.reason ?? "Remove failed.", false);
      }
    } catch {
      showToast("Remove failed.", false);
    } finally {
      setRemoving(null);
    }
  }, [token, requireElevation, refresh, showToast]);

  const handleRequestInstall = useCallback(async (skillId: string) => {
    if (!token) { return; }
    setBusy(skillId);
    try {
      const result = await occc.skillRequestInstall(token, skillId);
      if (result.outcome === "approved_immediate") {
        showToast(result.message, true);
        setTab("allowlist");
      } else if (result.outcome === "pending_user_ack" || result.outcome === "pending_admin_review") {
        showToast(result.message, true);
        setTab("pending");
      } else {
        showToast(result.message, false);
      }
      void refresh();
    } catch {
      showToast("Install request failed.", false);
    } finally {
      setBusy(null);
    }
  }, [token, refresh, showToast]);

  // Admin+ can approve/reject (operator and viewer cannot)
  const canAction = session?.role === "super-admin" || session?.role === "admin" || session?.role === "operator";

  if (loading) {
    return (
      <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "60vh" }}>
        <div className="spinner" />
      </div>
    );
  }

  const pendingSkillIds = new Set(pending.map((r) => r.skillId));
  const allowlistSkillIds = new Set(allowlist.map((e) => e.skillId));
  const installableEntries = catalog.filter(
    (e) => e.approvalLevel !== "blocked" && !allowlistSkillIds.has(e.id) && !pendingSkillIds.has(e.id),
  );

  const filteredCatalog = catalogSearch
    ? installableEntries.filter(
        (e) =>
          e.name.toLowerCase().includes(catalogSearch.toLowerCase()) ||
          e.description.toLowerCase().includes(catalogSearch.toLowerCase()) ||
          e.category.toLowerCase().includes(catalogSearch.toLowerCase()),
      )
    : installableEntries;

  return (
    <div>
      {/* Page header */}
      <div className="page-header">
        <div>
          <h1>Skill Governance</h1>
          <p>Approval pipeline, allowlist, and skill installation requests</p>
        </div>
        <button onClick={() => void refresh()} style={st.refreshBtn} title="Refresh">
          ↻ Refresh
        </button>
      </div>

      {/* Toast */}
      {toast && (
        <div
          style={{
            ...st.toast,
            background: toast.ok ? "var(--accent-success)" : "var(--accent-danger)",
          }}
          role="status"
          aria-live="polite"
        >
          {toast.msg}
        </div>
      )}

      {/* Stats */}
      <div style={st.statsRow}>
        <StatPill label="Pending" value={pending.length} color="var(--accent-warning)" />
        <StatPill label="Approved" value={allowlist.length} color="var(--accent-success)" />
        <StatPill label="Available" value={installableEntries.length} color="var(--accent-primary)" />
      </div>

      {/* Tabs */}
      <div style={st.tabBar} role="tablist">
        <TabButton active={tab === "pending"} badge={pending.length} onClick={() => setTab("pending")}>
          Pending Reviews
        </TabButton>
        <TabButton active={tab === "allowlist"} onClick={() => setTab("allowlist")}>
          Allowlist
        </TabButton>
        <TabButton active={tab === "catalog"} onClick={() => setTab("catalog")}>
          Skill Catalog
        </TabButton>
      </div>

      {/* Pending */}
      {tab === "pending" && (
        <div style={st.section}>
          {pending.length === 0 ? (
            <EmptyState icon="✓" message="No pending skill requests" />
          ) : (
            <div style={st.cardList}>
              {pending.map((req) => (
                <SkillRequestCard
                  key={req.id}
                  request={req}
                  elevated={canAction}
                  onApprove={handleApprove}
                  onReject={handleReject}
                  busy={busy === req.id}
                />
              ))}
            </div>
          )}
        </div>
      )}

      {/* Allowlist */}
      {tab === "allowlist" && (
        <div style={st.section}>
          <SkillAllowlistPanel
            entries={allowlist}
            onRemove={handleRemove}
            removing={removing}
          />
        </div>
      )}

      {/* Catalog */}
      {tab === "catalog" && (
        <div style={st.section}>
          <div style={st.catalogControls}>
            <input
              type="text"
              placeholder="Search catalog…"
              value={catalogSearch}
              onChange={(e) => setCatalogSearch(e.target.value)}
              style={st.searchInput}
              aria-label="Search skill catalog"
            />
          </div>
          {filteredCatalog.length === 0 ? (
            <EmptyState icon="◈" message={catalogSearch ? "No skills match your search" : "All available skills are already installed or pending"} />
          ) : (
            <div style={st.cardList}>
              {filteredCatalog.map((entry) => (
                <CatalogCard
                  key={entry.id}
                  entry={entry}
                  onRequest={handleRequestInstall}
                  busy={busy === entry.id}
                />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Sub-components ──────────────────────────────────────────────────────────

function StatPill({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div style={st.statPill}>
      <span style={{ fontSize: "20px", fontWeight: 700, color, lineHeight: 1 }}>{value}</span>
      <span style={{ fontSize: "10px", color: "var(--text-tertiary)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
        {label}
      </span>
    </div>
  );
}

function TabButton({
  active,
  badge,
  onClick,
  children,
}: {
  active: boolean;
  badge?: number;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      role="tab"
      aria-selected={active}
      onClick={onClick}
      style={{ ...st.tabBtn, ...(active ? st.tabBtnActive : {}) }}
    >
      {children}
      {badge !== undefined && badge > 0 && (
        <span style={st.tabBadge}>{badge}</span>
      )}
    </button>
  );
}

function EmptyState({ icon, message }: { icon: string; message: string }) {
  return (
    <div style={st.empty}>
      <div style={{ fontSize: "28px", opacity: 0.3, marginBottom: "8px" }}>{icon}</div>
      <span>{message}</span>
    </div>
  );
}

function CatalogCard({
  entry,
  onRequest,
  busy,
}: {
  entry: SkillCatalogEntry;
  onRequest: (id: string) => void;
  busy: boolean;
}) {
  return (
    <div style={st.catalogCard}>
      <div style={st.catalogInfo}>
        <div style={st.catalogHeader}>
          <span style={st.catalogName}>{entry.name}</span>
          <span style={{ ...st.badge, color: RISK_COLOR[entry.riskLevel] }}>
            {entry.riskLevel}
          </span>
          <span style={{ ...st.badge, color: APPROVAL_LEVEL_COLOR[entry.approvalLevel] ?? "var(--text-tertiary)" }}>
            {APPROVAL_LEVEL_LABEL[entry.approvalLevel] ?? entry.approvalLevel}
          </span>
          {entry.recommended && (
            <span style={{ ...st.badge, color: "var(--accent-primary)" }}>★ Recommended</span>
          )}
        </div>
        <p style={st.catalogDesc}>{entry.description}</p>
        <span style={st.catalogCategory}>{entry.category}</span>
      </div>

      <button
        style={st.requestBtn}
        disabled={busy}
        onClick={() => onRequest(entry.id)}
        aria-label={`Request install for ${entry.name}`}
      >
        {busy ? "…" : "Request Install"}
      </button>
    </div>
  );
}

// ─── Styles ──────────────────────────────────────────────────────────────────

const st: Record<string, React.CSSProperties> = {
  statsRow: {
    display: "flex",
    gap: "12px",
    marginBottom: "24px",
  },
  statPill: {
    display: "flex",
    flexDirection: "column" as React.CSSProperties["flexDirection"],
    alignItems: "center",
    gap: "4px",
    background: "var(--surface-1)",
    border: "1px solid var(--border-subtle)",
    borderRadius: "10px",
    padding: "14px 24px",
    minWidth: "88px",
  },
  tabBar: {
    display: "flex",
    gap: "2px",
    borderBottom: "1px solid var(--border-subtle)",
    marginBottom: "20px",
  },
  tabBtn: {
    background: "none",
    border: "none",
    borderBottom: "2px solid transparent",
    padding: "10px 16px",
    fontSize: "13px",
    color: "var(--text-tertiary)",
    cursor: "pointer",
    display: "flex",
    alignItems: "center",
    gap: "6px",
    marginBottom: "-1px",
    borderRadius: "0",
    transition: "color 150ms",
  },
  tabBtnActive: {
    color: "var(--text-primary)",
    borderBottom: "2px solid var(--accent-primary)",
    fontWeight: 600,
  },
  tabBadge: {
    background: "var(--accent-warning)",
    color: "white",
    borderRadius: "10px",
    padding: "1px 6px",
    fontSize: "10px",
    fontWeight: 700,
    lineHeight: "16px",
  },
  section: {
    minHeight: "200px",
  },
  cardList: {
    display: "flex",
    flexDirection: "column" as React.CSSProperties["flexDirection"],
    gap: "12px",
  },
  empty: {
    textAlign: "center" as React.CSSProperties["textAlign"],
    padding: "56px 20px",
    color: "var(--text-tertiary)",
    fontSize: "13px",
  },
  toast: {
    position: "fixed" as React.CSSProperties["position"],
    bottom: "24px",
    right: "24px",
    padding: "12px 20px",
    borderRadius: "8px",
    color: "white",
    fontSize: "13px",
    fontWeight: 600,
    zIndex: 9999,
    boxShadow: "var(--shadow-lg)",
    maxWidth: "320px",
  },
  refreshBtn: {
    background: "var(--surface-1)",
    border: "1px solid var(--border-default)",
    borderRadius: "8px",
    padding: "8px 14px",
    fontSize: "13px",
    color: "var(--text-secondary)",
    cursor: "pointer",
  },
  catalogControls: {
    marginBottom: "16px",
  },
  searchInput: {
    background: "var(--surface-1)",
    border: "1px solid var(--border-subtle)",
    borderRadius: "8px",
    padding: "8px 12px",
    fontSize: "13px",
    color: "var(--text-primary)",
    outline: "none",
    width: "240px",
  },
  catalogCard: {
    background: "var(--surface-1)",
    border: "1px solid var(--border-subtle)",
    borderRadius: "10px",
    padding: "16px",
    display: "flex",
    alignItems: "flex-start",
    gap: "16px",
  },
  catalogInfo: {
    flex: 1,
    minWidth: 0,
  },
  catalogHeader: {
    display: "flex",
    alignItems: "center",
    gap: "8px",
    flexWrap: "wrap" as React.CSSProperties["flexWrap"],
    marginBottom: "6px",
  },
  catalogName: {
    fontSize: "15px",
    fontWeight: 600,
    color: "var(--text-primary)",
  },
  catalogDesc: {
    fontSize: "13px",
    color: "var(--text-secondary)",
    lineHeight: 1.5,
    margin: "0 0 6px 0",
  },
  catalogCategory: {
    fontSize: "10px",
    textTransform: "uppercase" as React.CSSProperties["textTransform"],
    letterSpacing: "0.05em",
    color: "var(--text-muted)",
  },
  badge: {
    fontSize: "10px",
    fontWeight: 700,
    textTransform: "uppercase" as React.CSSProperties["textTransform"],
    letterSpacing: "0.04em",
    padding: "2px 6px",
    borderRadius: "4px",
    background: "var(--surface-2)",
  },
  requestBtn: {
    background: "linear-gradient(135deg, #6366f1, #4f46e5)",
    border: "none",
    borderRadius: "7px",
    padding: "8px 14px",
    fontSize: "12px",
    fontWeight: 600,
    color: "white",
    cursor: "pointer",
    whiteSpace: "nowrap" as React.CSSProperties["whiteSpace"],
    flexShrink: 0,
  },
};
