/**
 * InstallerWizard — Step: Automated Backups (GitHub)
 *
 * Validates a PAT and auto-creates a private backup repo. Both IPC calls use
 * typed OcccBridge methods — no occc.invoke() usage.
 */

import React, { useState } from "react";
import type { OcccBridge } from "../../../shared/ipc-types.js";
import type { WizardConfig } from "./installer-types.js";
import { step, btnPrimary, btnSecondary, btnDisabled, labelStyle, inputStyle } from "./installer-styles.js";

const occc = (window as unknown as { occc: OcccBridge }).occc;

interface StepGitHubProps {
  config: WizardConfig;
  setConfig: React.Dispatch<React.SetStateAction<WizardConfig>>;
  onNext: () => void;
}

export function StepGitHub({ config, setConfig, onNext }: StepGitHubProps) {
  const [validating, setValidating] = useState(false);
  const [result, setResult] = useState<{
    ok: boolean;
    login?: string;
    repoUrl?: string;
    error?: string;
  } | null>(null);

  const handleValidate = async () => {
    if (!config.githubPat) { return; }
    setValidating(true);
    setResult(null);
    try {
      const patResult = await occc.installGitHubValidatePAT(config.githubPat);
      if (!patResult.valid) {
        setResult({ ok: false, error: "Invalid Personal Access Token." });
        return;
      }
      const repoResult = await occc.installGitHubCreateRepo(config.githubPat);
      setConfig((c) => ({ ...c, githubRepo: repoResult.url }));
      setResult({ ok: true, login: patResult.login, repoUrl: repoResult.url });
    } catch {
      setResult({ ok: false, error: "Failed to connect to GitHub." });
    } finally {
      setValidating(false);
    }
  };

  return (
    <div style={step.container}>
      <h2 style={step.heading}>Automated Backups</h2>
      <p style={step.desc}>
        OpenClaw will automatically back up your configuration to a private GitHub repository.
        Provide a Personal Access Token with <strong>repo</strong> scope.
      </p>

      <div
        style={{
          background: "var(--surface-1)",
          border: "1px solid var(--border-subtle)",
          borderRadius: "12px",
          padding: "20px",
          margin: "16px 0",
        }}
      >
        <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
          <div>
            <label style={labelStyle} htmlFor="github-pat">
              GitHub Personal Access Token
            </label>
            <input
              id="github-pat"
              style={inputStyle}
              type="password"
              value={config.githubPat}
              onChange={(e) => {
                setConfig((c) => ({ ...c, githubPat: e.target.value }));
                setResult(null);
              }}
              placeholder="ghp_…"
            />
            <a
              href="https://github.com/settings/tokens/new?scopes=repo&description=OpenClaw+Backup"
              target="_blank"
              rel="noreferrer noopener"
              style={{
                fontSize: "11px",
                color: "var(--accent-primary-hover)",
                marginTop: "6px",
                display: "block",
                textDecoration: "none",
              }}
            >
              How to create a PAT (repo scope) →
            </a>
          </div>

          <button
            style={validating ? btnDisabled : btnSecondary}
            onClick={handleValidate}
            disabled={validating || !config.githubPat}
          >
            {validating ? "Validating…" : "Validate & Create Repo"}
          </button>

          {result && (
            <div
              style={{
                fontSize: "13px",
                color: result.ok ? "var(--accent-success)" : "var(--accent-danger)",
              }}
            >
              {result.ok
                ? `✓ Connected as @${result.login ?? "unknown"}. Repository: ${result.repoUrl}`
                : `✗ ${result.error}`}
            </div>
          )}
        </div>
      </div>

      <div style={step.actions}>
        <button style={btnSecondary} onClick={onNext}>
          Skip (configure later)
        </button>
        <button style={result?.ok ? btnPrimary : btnSecondary} onClick={onNext}>
          {result?.ok ? "Continue →" : "Continue without Backup →"}
        </button>
      </div>
    </div>
  );
}
