/**
 * InstallerWizard — Step: Container Engine
 *
 * Detects whether Docker is already running; if not, offers direct links to
 * Docker Desktop (GUI) or Docker CE (headless). All IPC via typed OcccBridge.
 */

import React, { useState, useEffect, useCallback } from "react";
import type { OcccBridge } from "../../../shared/ipc-types.js";
import { step, btnPrimary, btnSecondary } from "./installer-styles.js";

const occc = (window as unknown as { occc: OcccBridge }).occc;

interface StepDockerProps {
  onNext: () => void;
}

export function StepDocker({ onNext }: StepDockerProps) {
  const [verify, setVerify] = useState<{ ok: boolean; version?: string; error?: string } | null>(
    null,
  );
  const [checking, setChecking] = useState(false);
  const [waitMsg, setWaitMsg] = useState<string | null>(null);
  const [options, setOptions] = useState<{ dockerDesktop: boolean; dockerCE: boolean }>({
    dockerDesktop: true,
    dockerCE: false,
  });
  const [ceCmd, setCeCmd] = useState<string | null>(null);

  const checkDocker = useCallback(async () => {
    setChecking(true);
    try {
      const result = await occc.installVerifyDocker();
      setVerify(result);
    } finally {
      setChecking(false);
    }
  }, []);

  useEffect(() => {
    occc.installGetDockerOptions().then((v) => setOptions(v)).catch(() => {});
    void checkDocker();
  }, [checkDocker]);

  const handleOpenDesktop = async () => {
    await occc.installOpenDockerDownload();
    setWaitMsg("Download Docker Desktop, install it, then click the button below.");
  };

  const handleShowCE = async () => {
    const cmd = await occc.installGetDockerCECommand();
    setCeCmd(cmd);
  };

  return (
    <div style={step.container}>
      <h2 style={step.heading}>Container Engine</h2>
      <p style={step.desc}>
        OpenClaw runs in isolated containers. Install Docker Desktop (recommended) or Docker CE
        (headless).
      </p>

      {checking ? (
        <div style={step.center}>
          <div className="spinner" />
          <p style={{ color: "var(--text-tertiary)", marginTop: 12 }}>Checking…</p>
        </div>
      ) : verify?.ok ? (
        <div style={{ margin: "24px 0" }}>
          <div
            style={{
              ...step.alertBox,
              borderColor: "var(--accent-success)",
              color: "var(--accent-success)",
              background: "var(--accent-success-glow)",
            }}
          >
            ✓ Docker {verify.version} is installed and running
          </div>
          <div style={step.actions}>
            <button style={btnPrimary} onClick={onNext}>
              Continue →
            </button>
          </div>
        </div>
      ) : (
        <div style={{ margin: "24px 0", display: "flex", flexDirection: "column", gap: "12px" }}>
          <div style={step.alertBox}>{verify?.error ?? "No container engine detected."}</div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
            {options.dockerDesktop && (
              <OptionCard
                icon="🖥"
                title="Docker Desktop"
                desc="Full GUI experience. Recommended for macOS and Windows."
                onClick={handleOpenDesktop}
                cta="Download Docker Desktop"
              />
            )}
            {options.dockerCE && (
              <OptionCard
                icon="⚡"
                title="Docker CE"
                desc="Lightweight, command-line only. Best for Linux servers."
                onClick={handleShowCE}
                cta="Show Install Command"
              />
            )}
          </div>

          {ceCmd && (
            <div
              style={{
                background: "var(--surface-1)",
                border: "1px solid var(--border-default)",
                borderRadius: "10px",
                padding: "14px 16px",
              }}
            >
              <p
                style={{ fontSize: "12px", color: "var(--text-tertiary)", marginBottom: "8px" }}
              >
                Run this command in a terminal, then click Re-check:
              </p>
              <code
                style={{
                  fontSize: "12px",
                  color: "var(--accent-primary-hover)",
                  wordBreak: "break-all",
                  fontFamily: "var(--font-mono)",
                }}
              >
                {ceCmd}
              </code>
            </div>
          )}

          {waitMsg && (
            <p style={{ fontSize: "13px", color: "var(--text-secondary)", textAlign: "center" }}>
              {waitMsg}
            </p>
          )}

          <div style={step.actions}>
            <button style={btnSecondary} onClick={checkDocker}>
              ↺ Re-check
            </button>
            <button style={btnSecondary} onClick={onNext}>
              Skip (already installed)
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Sub-component ────────────────────────────────────────────────────────

function OptionCard({
  icon,
  title,
  desc,
  onClick,
  cta,
}: {
  icon: string;
  title: string;
  desc: string;
  onClick: () => void;
  cta: string;
}) {
  return (
    <div
      style={{
        background: "var(--surface-1)",
        border: "1px solid var(--border-default)",
        borderRadius: "12px",
        padding: "20px 16px",
        display: "flex",
        flexDirection: "column",
        gap: "12px",
      }}
    >
      <div style={{ fontSize: "28px" }}>{icon}</div>
      <div>
        <div style={{ fontWeight: 600, fontSize: "14px", marginBottom: "4px" }}>{title}</div>
        <div style={{ fontSize: "12px", color: "var(--text-secondary)", lineHeight: 1.5 }}>
          {desc}
        </div>
      </div>
      <button style={btnPrimary} onClick={onClick}>
        {cta}
      </button>
    </div>
  );
}
