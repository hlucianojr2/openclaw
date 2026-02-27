/**
 * Installation Wizard — multi-step guided setup UI.
 *
 * Steps:
 *   1. Welcome + System Check
 *   2. Container Engine (Docker Desktop or CE)
 *   3. AI Provider Selection
 *   4. Starter Skills
 *   5. Messaging Channels
 *   6. Advanced Settings (ports, voice)
 *   7. GitHub Backup Setup
 *   8. Review & Install
 *   9. Install Progress
 *  10. Complete
 *
 * All IPC calls use typed OcccBridge methods — occc.invoke() is not used here.
 */

import React, { useState, useEffect, useCallback } from "react";
import type { SystemCheck, SystemValidation, OcccBridge } from "../../../shared/ipc-types.js";
import type { WizardConfig } from "./installer-types.js";
import { StepDocker } from "./StepDocker.js";
import { StepLLM, LLM_OPTIONS } from "./StepLLM.js";
import { StepSkills } from "./StepSkills.js";
import { StepChannels } from "./StepChannels.js";
import { StepAdvanced } from "./StepAdvanced.js";
import { StepGitHub } from "./StepGitHub.js";
import { StepInstalling } from "./StepInstalling.js";
import { step, btnPrimary, btnSecondary, btnDisabled } from "./installer-styles.js";

const occc = (window as unknown as { occc: OcccBridge }).occc;

// ─── Wizard types ──────────────────────────────────────────────────────────

type WizardStep =
  | "welcome"
  | "docker"
  | "llm"
  | "skills"
  | "channels"
  | "advanced"
  | "github"
  | "review"
  | "installing"
  | "complete";

const STEPS: { id: WizardStep; label: string }[] = [
  { id: "welcome", label: "System" },
  { id: "docker", label: "Engine" },
  { id: "llm", label: "AI" },
  { id: "skills", label: "Skills" },
  { id: "channels", label: "Channels" },
  { id: "advanced", label: "Advanced" },
  { id: "github", label: "Backup" },
  { id: "review", label: "Review" },
  { id: "installing", label: "Install" },
];

const defaultConfig: WizardConfig = {
  llmProvider: "anthropic",
  llmApiKey: "",
  // Pre-select recommended skills from SKILL_CATALOG (auto-approved, recommended: true)
  selectedSkills: ["healthcheck", "session-logs", "model-usage", "summarize"],
  enabledChannels: [],
  githubPat: "",
  githubRepo: "",
  voiceEnabled: true,
  gatewayPort: 18789,
  bridgePort: 18790,
};

interface InstallerWizardProps {
  onComplete: () => void;
}

// ─── Wizard shell ──────────────────────────────────────────────────────────

export function InstallerWizard({ onComplete }: InstallerWizardProps) {
  const [step, setStep] = useState<WizardStep>("welcome");
  const [config, setConfig] = useState<WizardConfig>(defaultConfig);

  const stepIndex = STEPS.findIndex((s) => s.id === step);

  const goNext = useCallback((nextStep?: WizardStep) => {
    const next = nextStep ?? STEPS[stepIndex + 1]?.id;
    if (next) {setStep(next);}
  }, [stepIndex]);

  // Narrate each step via the typed bridge method
  useEffect(() => {
    const scripts: Partial<Record<WizardStep, string>> = {
      welcome: "Welcome to the OpenClaw setup wizard. Let's check your system requirements.",
      docker: "Now let's set up your container engine.",
      llm: "Choose your preferred AI provider.",
      skills: "Select the skills you want enabled from the start.",
      channels: "Pick the messaging channels you would like to activate.",
      advanced: "Review advanced settings like port numbers.",
      github: "Set up automated backups to GitHub.",
      review: "Review your configuration before installing.",
      installing: "Installing OpenClaw. Please wait.",
      complete: "Setup complete! OpenClaw is ready.",
    };
    const text = scripts[step];
    if (text && config.voiceEnabled) {
      occc.installVoiceSpeak(text).catch(() => {});
    }
  }, [step, config.voiceEnabled]);

  const toggleSkill = useCallback((id: string) => {
    setConfig((c) => ({
      ...c,
      selectedSkills: c.selectedSkills.includes(id)
        ? c.selectedSkills.filter((s) => s !== id)
        : [...c.selectedSkills, id],
    }));
  }, []);

  const toggleChannel = useCallback((id: string) => {
    setConfig((c) => ({
      ...c,
      enabledChannels: c.enabledChannels.includes(id)
        ? c.enabledChannels.filter((ch) => ch !== id)
        : [...c.enabledChannels, id],
    }));
  }, []);

  return (
    <div style={shell.page}>
      {/* Header */}
      <div style={shell.header}>
        <div style={shell.logo}>⬡</div>
        <h1 style={shell.title}>OpenClaw Setup</h1>

        {/* Quick voice toggle in header */}
        <button
          style={shell.voiceBtn}
          onClick={() => {
            const next = !config.voiceEnabled;
            setConfig((c) => ({ ...c, voiceEnabled: next }));
            occc.installVoiceSetEnabled(next).catch(() => {});
          }}
          title={config.voiceEnabled ? "Disable voice guide" : "Enable voice guide"}
        >
          {config.voiceEnabled ? "🔊" : "🔇"}
        </button>
      </div>

      {/* Progress bar */}
      <div style={shell.progressBar}>
        {STEPS.map((s, i) => (
          <div key={s.id} style={shell.progressItem}>
            <div style={{
              ...shell.progressDot,
              background: i < stepIndex
                ? "var(--accent-success)"
                : i === stepIndex
                ? "var(--accent-primary)"
                : "var(--surface-2)",
              boxShadow: i === stepIndex ? "0 0 12px rgba(99,102,241,0.4)" : "none",
            }}>
              {i < stepIndex ? "✓" : i + 1}
            </div>
            <span style={{ fontSize: "10px", color: i <= stepIndex ? "var(--text-secondary)" : "var(--text-muted)" }}>
              {s.label}
            </span>
          </div>
        ))}
        <div style={shell.progressLine}>
          <div style={{ ...shell.progressFill, width: `${(stepIndex / (STEPS.length - 1)) * 100}%` }} />
        </div>
      </div>

      {/* Step content */}
      <div style={shell.content}>
        {step === "welcome" && (
          <StepSystemCheck onNext={() => goNext("docker")} />
        )}
        {step === "docker" && (
          <StepDocker onNext={() => goNext("llm")} />
        )}
        {step === "llm" && (
          <StepLLM
            config={config}
            setConfig={setConfig}
            onNext={() => goNext("skills")}
          />
        )}
        {step === "skills" && (
          <StepSkills
            selectedSkills={config.selectedSkills}
            onToggle={toggleSkill}
            onNext={() => goNext("channels")}
          />
        )}
        {step === "channels" && (
          <StepChannels
            enabledChannels={config.enabledChannels}
            onToggle={toggleChannel}
            onNext={() => goNext("advanced")}
          />
        )}
        {step === "advanced" && (
          <StepAdvanced
            config={{
              gatewayPort: config.gatewayPort,
              bridgePort: config.bridgePort,
              voiceEnabled: config.voiceEnabled,
            }}
            onChange={(patch) => setConfig((c) => ({ ...c, ...patch }))}
            onNext={() => goNext("github")}
          />
        )}
        {step === "github" && (
          <StepGitHub
            config={config}
            setConfig={setConfig}
            onNext={() => goNext("review")}
          />
        )}
        {step === "review" && (
          <StepReview
            config={config}
            onInstall={() => setStep("installing")}
          />
        )}
        {step === "installing" && (
          <StepInstalling
            config={config}
            onComplete={() => setStep("complete")}
          />
        )}
        {step === "complete" && (
          <StepComplete onFinish={onComplete} />
        )}
      </div>
    </div>
  );
}

// ─── Step 1: System Check ─────────────────────────────────────────────────

function StepSystemCheck({ onNext }: { onNext: () => void }) {
  const [validation, setValidation] = useState<SystemValidation | null>(null);
  const [loading, setLoading] = useState(true);
  const [_retrying, setRetrying] = useState(false);

  const runCheck = useCallback(async () => {
    setLoading(true);
    try {
      const result = await occc.installValidateSystem();
      setValidation(result);
    } catch {
      setValidation(null);
    } finally {
      setLoading(false);
      setRetrying(false);
    }
  }, []);

  useEffect(() => { void runCheck(); }, [runCheck]);

  const retry = () => { setRetrying(true); setValidation(null); void runCheck(); };

  return (
    <div style={step.container}>
      <h2 style={step.heading}>System Requirements</h2>
      <p style={step.desc}>Checking your system before we begin.</p>

      {loading ? (
        <div style={step.center}>
          <div className="spinner" />
          <p style={{ color: "var(--text-tertiary)", marginTop: "12px" }}>Running checks…</p>
        </div>
      ) : validation ? (
        <>
          <div style={{ display: "flex", flexDirection: "column", gap: "10px", margin: "24px 0" }}>
            {validation.checks.map((c) => (
              <CheckRow key={c.name} check={c} />
            ))}
          </div>

          {!validation.canProceed && (
            <div style={step.alertBox}>
              <strong>Some required checks failed.</strong> Please resolve the issues above before continuing.
            </div>
          )}

          <div style={step.actions}>
            <button style={btnSecondary} onClick={retry}>
              ↺ Re-run Checks
            </button>
            <button
              style={validation.canProceed ? btnPrimary : btnDisabled}
              disabled={!validation.canProceed}
              onClick={onNext}
            >
              {validation.allPassed ? "Continue →" : "Continue with Warnings →"}
            </button>
          </div>
        </>
      ) : (
        <div style={step.center}>
          <p style={{ color: "var(--accent-danger)" }}>Could not run system checks.</p>
          <button style={btnPrimary} onClick={retry}>Try Again</button>
        </div>
      )}
    </div>
  );
}

function CheckRow({ check }: { check: SystemCheck }) {
  const icons = { pass: "✓", warn: "⚠", fail: "✗" };
  const colors = {
    pass: "var(--accent-success)",
    warn: "var(--accent-warning)",
    fail: "var(--accent-danger)",
  };
  return (
    <div style={{ display: "flex", alignItems: "flex-start", gap: "12px", padding: "12px 16px", background: "var(--surface-1)", borderRadius: "10px", border: "1px solid var(--border-subtle)" }}>
      <span style={{ fontSize: "16px", color: colors[check.result], flexShrink: 0, marginTop: "1px" }}>
        {icons[check.result]}
      </span>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: "13px", fontWeight: 600, color: "var(--text-primary)" }}>{check.name}</div>
        <div style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "2px" }}>{check.message}</div>
      </div>
    </div>
  );
}

// ─── Steps 2–3, 4, 6 (extracted) ─────────────────────────────────────────
// StepDocker → StepDocker.tsx
// StepLLM    → StepLLM.tsx
// StepGitHub → StepGitHub.tsx
// StepInstalling → StepInstalling.tsx

// ─── Step 5: Review ───────────────────────────────────────────────────────

function StepReview({ config, onInstall }: { config: WizardConfig; onInstall: () => void }) {
  const llm = LLM_OPTIONS.find((o) => o.id === config.llmProvider);

  return (
    <div style={step.container}>
      <h2 style={step.heading}>Review & Install</h2>
      <p style={step.desc}>Everything looks good. Review your configuration and click Install to begin.</p>

      <div style={{ display: "flex", flexDirection: "column", gap: "8px", margin: "20px 0" }}>
        <ReviewRow label="AI Provider" value={`${llm?.icon} ${llm?.label}`} />
        <ReviewRow label="API Key" value={config.llmApiKey ? "••••••••" : "Not set"} />
        <ReviewRow label="Skills" value={config.selectedSkills.length > 0 ? `${config.selectedSkills.length} selected` : "None selected"} />
        <ReviewRow label="Channels" value={config.enabledChannels.length > 0 ? `${config.enabledChannels.length} enabled` : "None selected"} />
        <ReviewRow label="Backup" value={config.githubRepo || "Not configured"} />
        <ReviewRow label="Gateway Port" value={String(config.gatewayPort)} />
        <ReviewRow label="Bridge Port" value={String(config.bridgePort)} />
        <ReviewRow label="Voice Guide" value={config.voiceEnabled ? "Enabled" : "Disabled"} />
      </div>

      <div style={step.actions}>
        <button style={btnPrimary} onClick={onInstall}>
          ⬡ Install OpenClaw
        </button>
      </div>
    </div>
  );
}

function ReviewRow({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 14px", background: "var(--surface-1)", borderRadius: "8px" }}>
      <span style={{ fontSize: "13px", color: "var(--text-secondary)" }}>{label}</span>
      <span style={{ fontSize: "13px", fontWeight: 500, color: "var(--text-primary)" }}>{value}</span>
    </div>
  );
}

// ─── Step 6: Installing (see StepInstalling.tsx) ────────────────────────────

// ─── Step 7: Complete ─────────────────────────────────────────────────────

function StepComplete({ onFinish }: { onFinish: () => void }) {
  return (
    <div style={{ ...step.container, textAlign: "center" }}>
      <div style={{ fontSize: "56px", margin: "20px 0 16px" }}>🎉</div>
      <h2 style={{ fontSize: "22px", fontWeight: 700, margin: "0 0 12px" }}>OpenClaw is Ready!</h2>
      <p style={{ color: "var(--text-secondary)", lineHeight: 1.6, margin: "0 0 32px" }}>
        Your secure OpenClaw environment is installed and running. Head to the dashboard to monitor your environment and start configuring your agents.
      </p>
      <button style={btnPrimary} onClick={onFinish}>
        Go to Dashboard →
      </button>
    </div>
  );
}

// ─── Shared styles ────────────────────────────────────────────────────────

const shell: Record<string, React.CSSProperties> = {
  page: { display: "flex", flexDirection: "column", height: "100%", background: "var(--bg-primary)", overflow: "hidden" },
  header: { display: "flex", alignItems: "center", gap: "12px", padding: "20px 32px 0", paddingTop: "50px" },
  logo: { fontSize: "24px", background: "linear-gradient(135deg, #6366f1, #22c55e)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" },
  title: { fontSize: "17px", fontWeight: 700, color: "var(--text-primary)", margin: 0, flex: 1 },
  voiceBtn: { background: "none", border: "none", cursor: "pointer", fontSize: "18px", padding: "4px 8px" },
  progressBar: { display: "flex", alignItems: "flex-start", justifyContent: "center", gap: "0", padding: "20px 48px 16px", position: "relative" },
  progressItem: { display: "flex", flexDirection: "column", alignItems: "center", gap: "6px", flex: 1, position: "relative", zIndex: 1 },
  progressDot: { width: "28px", height: "28px", borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", fontSize: "11px", fontWeight: 700, color: "white", transition: "all 300ms" },
  progressLine: { position: "absolute", top: "34px", left: "calc(50% / 9 + 32px)", right: "calc(50% / 9 + 32px)", height: "2px", background: "var(--surface-2)", zIndex: 0 },
  progressFill: { height: "100%", background: "var(--accent-primary)", transition: "width 400ms" },
  content: { flex: 1, overflowY: "auto", padding: "0 32px 32px" },
};
// Style constants (step, labelStyle, inputStyle, btnPrimary, btnSecondary, btnDisabled)
// are imported from ./installer-styles.ts — see import block at top of file.
