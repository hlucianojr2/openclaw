/**
 * InstallerWizard — Step: Installing
 *
 * Fires off the actual installation and displays live progress. Subscribes to
 * "occc:install:progress" events and cleans up the listener on unmount.
 *
 * Key fixes:
 *  - BLOCKER: passes selectedChannels: ChannelSelection[] (not enabledChannels: string[])
 *  - IMPORTANT-2: useEffect returns occc.off() cleanup to prevent listener leak
 */

import React, { useState, useEffect, useRef } from "react";
import type { OcccBridge } from "../../../shared/ipc-types.js";
import type { WizardConfig, InstallProgress } from "./installer-types.js";
import { step } from "./installer-styles.js";

const occc = (window as unknown as { occc: OcccBridge }).occc;

interface StepInstallingProps {
  config: WizardConfig;
  onComplete: () => void;
}

export function StepInstalling({ config, onComplete }: StepInstallingProps) {
  const [progress, setProgress] = useState<InstallProgress>({
    stage: "preparing",
    percent: 0,
    message: "Preparing…",
  });
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) { return; }
    started.current = true;

    // Extract handler so we can pass the same reference to occc.off() on cleanup.
    const handler = (...args: unknown[]) => {
      const p = args[0] as InstallProgress;
      setProgress(p);
      if (p.stage === "done") { onComplete(); }
      if (p.stage === "error") { setError(p.error ?? "Installation failed."); }
    };

    occc.on("occc:install:progress", handler);

    // BLOCKER fix: map string[] → ChannelSelection[] before sending to main.
    // Backend (installer-engine) expects { channelId, config } objects, not raw IDs.
    occc
      .installRun({
        llmProvider: config.llmProvider,
        llmApiKey: config.llmApiKey,
        selectedSkills: config.selectedSkills,
        selectedChannels: config.enabledChannels.map((id) => ({
          channelId: id,
          config: {},
        })),
        githubPat: config.githubPat,
        githubRepo: config.githubRepo,
        voiceEnabled: config.voiceEnabled,
        gatewayPort: config.gatewayPort,
        bridgePort: config.bridgePort,
      })
      .catch((err: Error) => {
        setError(err.message);
      });

    // IMPORTANT-2: clean up the listener on unmount to prevent memory/event leak.
    return () => {
      occc.off("occc:install:progress", handler);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div style={step.container}>
      <h2 style={step.heading}>Installing…</h2>
      {!error ? (
        <>
          <div style={{ margin: "32px 0 16px" }}>
            <div style={progressTrack}>
              <div
                style={{
                  ...progressFill,
                  width: `${progress.percent}%`,
                  transition: "width 500ms var(--ease-out)",
                }}
              />
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", marginTop: "8px" }}>
              <p style={{ fontSize: "13px", color: "var(--text-secondary)" }}>
                {progress.message}
              </p>
              <span style={{ fontSize: "13px", color: "var(--text-tertiary)" }}>
                {progress.percent}%
              </span>
            </div>
          </div>

          <div style={{ display: "flex", justifyContent: "center", marginTop: "16px" }}>
            <div className="spinner" />
          </div>
        </>
      ) : (
        <div style={{ margin: "24px 0" }}>
          <div
            style={{
              ...step.alertBox,
              borderColor: "var(--accent-danger)",
              color: "var(--accent-danger)",
            }}
          >
            ✗ {error}
          </div>
          <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginTop: "12px" }}>
            Check that Docker is running and try again. If the problem persists, check the logs.
          </p>
        </div>
      )}
    </div>
  );
}

// ─── Local styles (only used here) ───────────────────────────────────────

const progressTrack: React.CSSProperties = {
  height: "8px",
  background: "var(--surface-2)",
  borderRadius: "4px",
  overflow: "hidden",
};

const progressFill: React.CSSProperties = {
  height: "100%",
  background: "linear-gradient(90deg, var(--accent-primary), var(--accent-success))",
  borderRadius: "4px",
};
