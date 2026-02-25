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

import React, { useState, useEffect, useCallback, useRef } from "react";
import type { SystemCheck, SystemValidation, OcccBridge } from "../../../shared/ipc-types.js";
import { StepSkills } from "./StepSkills.js";
import { StepChannels } from "./StepChannels.js";
import { StepAdvanced } from "./StepAdvanced.js";

// Defined in renderer to avoid importing from main-process (renderer boundary)
type LLMProvider = "anthropic" | "google-gemini" | "openai" | "ollama";

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

interface WizardConfig {
  llmProvider: LLMProvider;
  llmApiKey: string;
  selectedSkills: string[];
  enabledChannels: string[];
  githubPat: string;
  githubRepo: string;
  voiceEnabled: boolean;
  gatewayPort: number;
  bridgePort: number;
}

const defaultConfig: WizardConfig = {
  llmProvider: "anthropic",
  llmApiKey: "",
  // Pre-select the three recommended skills
  selectedSkills: ["memory-core", "brave-search", "llm-task"],
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

// ─── Step 2: Docker ───────────────────────────────────────────────────────

function StepDocker({ onNext }: { onNext: () => void }) {
  const [verify, setVerify] = useState<{ ok: boolean; version?: string; error?: string } | null>(null);
  const [checking, setChecking] = useState(false);
  const [waitMsg, setWaitMsg] = useState<string | null>(null);
  const [options, setOptions] = useState<{ dockerDesktop: boolean; dockerCE: boolean }>({
    dockerDesktop: true,
    dockerCE: false,
  });
  const [ceCmd, setCeCmd] = useState<string | null>(null);

  useEffect(() => {
    occc.installGetDockerOptions().then((v) => setOptions(v)).catch(() => {});
    void checkDocker();
  }, []);

  const checkDocker = async () => {
    setChecking(true);
    try {
      const result = await occc.installVerifyDocker();
      setVerify(result);
    } finally {
      setChecking(false);
    }
  };

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
        OpenClaw runs in isolated containers. Install Docker Desktop (recommended) or Docker CE (headless).
      </p>

      {checking ? (
        <div style={step.center}><div className="spinner" /><p style={{ color: "var(--text-tertiary)", marginTop: 12 }}>Checking…</p></div>
      ) : verify?.ok ? (
        <div style={{ margin: "24px 0" }}>
          <div style={{ ...step.alertBox, borderColor: "var(--accent-success)", color: "var(--accent-success)", background: "var(--accent-success-glow)" }}>
            ✓ Docker {verify.version} is installed and running
          </div>
          <div style={step.actions}>
            <button style={btnPrimary} onClick={onNext}>Continue →</button>
          </div>
        </div>
      ) : (
        <div style={{ margin: "24px 0", display: "flex", flexDirection: "column", gap: "12px" }}>
          <div style={step.alertBox}>
            {verify?.error ?? "No container engine detected."}
          </div>

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
            <div style={{ background: "var(--surface-1)", border: "1px solid var(--border-default)", borderRadius: "10px", padding: "14px 16px" }}>
              <p style={{ fontSize: "12px", color: "var(--text-tertiary)", marginBottom: "8px" }}>Run this command in a terminal, then click Re-check:</p>
              <code style={{ fontSize: "12px", color: "var(--accent-primary-hover)", wordBreak: "break-all", fontFamily: "var(--font-mono)" }}>
                {ceCmd}
              </code>
            </div>
          )}

          {waitMsg && (
            <p style={{ fontSize: "13px", color: "var(--text-secondary)", textAlign: "center" }}>{waitMsg}</p>
          )}

          <div style={step.actions}>
            <button style={btnSecondary} onClick={checkDocker}>↺ Re-check</button>
            <button style={btnSecondary} onClick={onNext}>Skip (already installed)</button>
          </div>
        </div>
      )}
    </div>
  );
}

function OptionCard({ icon, title, desc, onClick, cta }: { icon: string; title: string; desc: string; onClick: () => void; cta: string; }) {
  return (
    <div style={{ background: "var(--surface-1)", border: "1px solid var(--border-default)", borderRadius: "12px", padding: "20px 16px", display: "flex", flexDirection: "column", gap: "12px" }}>
      <div style={{ fontSize: "28px" }}>{icon}</div>
      <div>
        <div style={{ fontWeight: 600, fontSize: "14px", marginBottom: "4px" }}>{title}</div>
        <div style={{ fontSize: "12px", color: "var(--text-secondary)", lineHeight: 1.5 }}>{desc}</div>
      </div>
      <button style={btnPrimary} onClick={onClick}>{cta}</button>
    </div>
  );
}

// ─── Step 3: LLM Provider ─────────────────────────────────────────────────

const LLM_OPTIONS: { id: LLMProvider; label: string; desc: string; icon: string; keyLabel: string; keyPlaceholder: string; keyUrl: string }[] = [
  { id: "anthropic", label: "Anthropic Claude", desc: "Best reasoning & safety. Recommended.", icon: "🤖", keyLabel: "Anthropic API Key", keyPlaceholder: "sk-ant-…", keyUrl: "https://console.anthropic.com/settings/keys" },
  { id: "google-gemini", label: "Google Gemini", desc: "Powerful multimodal model from Google.", icon: "✦", keyLabel: "Gemini API Key", keyPlaceholder: "AIza…", keyUrl: "https://aistudio.google.com/app/apikey" },
  { id: "openai", label: "OpenAI", desc: "GPT-4o and family of models.", icon: "◎", keyLabel: "OpenAI API Key", keyPlaceholder: "sk-…", keyUrl: "https://platform.openai.com/api-keys" },
  { id: "ollama", label: "Ollama (Local)", desc: "Fully local, no API key required.", icon: "🦙", keyLabel: "", keyPlaceholder: "", keyUrl: "" },
];

function StepLLM({ config, setConfig, onNext }: { config: WizardConfig; setConfig: React.Dispatch<React.SetStateAction<WizardConfig>>; onNext: () => void }) {
  const selected = LLM_OPTIONS.find((o) => o.id === config.llmProvider)!;

  return (
    <div style={step.container}>
      <h2 style={step.heading}>AI Provider</h2>
      <p style={step.desc}>Choose your preferred language model. You can change this later in Configuration.</p>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px", margin: "20px 0 16px" }}>
        {LLM_OPTIONS.map((opt) => (
          <div
            key={opt.id}
            onClick={() => setConfig((c) => ({ ...c, llmProvider: opt.id, llmApiKey: "" }))}
            style={{
              padding: "14px 16px",
              background: config.llmProvider === opt.id ? "var(--accent-primary-glow)" : "var(--surface-1)",
              border: `1px solid ${config.llmProvider === opt.id ? "var(--accent-primary)" : "var(--border-subtle)"}`,
              borderRadius: "12px",
              cursor: "pointer",
              transition: "all 200ms",
            }}
          >
            <span style={{ fontSize: "20px" }}>{opt.icon}</span>
            <div style={{ fontWeight: 600, fontSize: "13px", marginTop: "6px" }}>{opt.label}</div>
            <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "3px" }}>{opt.desc}</div>
          </div>
        ))}
      </div>

      {selected.keyLabel && (
        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
          <label style={labelStyle}>{selected.keyLabel}</label>
          <input
            style={inputStyle}
            type="password"
            value={config.llmApiKey}
            onChange={(e) => setConfig((c) => ({ ...c, llmApiKey: e.target.value }))}
            placeholder={selected.keyPlaceholder}
          />
          {selected.keyUrl && (
            <a
              href={selected.keyUrl}
              target="_blank"
              rel="noreferrer noopener"
              style={{ fontSize: "12px", color: "var(--accent-primary-hover)", textDecoration: "none" }}
            >
              Get API key →
            </a>
          )}
        </div>
      )}

      <div style={step.actions}>
        <button
          style={config.llmProvider === "ollama" || config.llmApiKey ? btnPrimary : btnSecondary}
          onClick={onNext}
        >
          Continue →
        </button>
      </div>
    </div>
  );
}

// ─── Step 4: GitHub Backup ────────────────────────────────────────────────

function StepGitHub({ config, setConfig, onNext }: { config: WizardConfig; setConfig: React.Dispatch<React.SetStateAction<WizardConfig>>; onNext: () => void }) {
  const [validating, setValidating] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; login?: string; repoUrl?: string; error?: string } | null>(null);

  const handleValidate = async () => {
    if (!config.githubPat) {return;}
    setValidating(true);
    setResult(null);
    try {
      // Validate the PAT via typed bridge method
      const patResult = await occc.installGitHubValidatePAT(config.githubPat);
      if (!patResult.valid) {
        setResult({ ok: false, error: "Invalid Personal Access Token." });
        return;
      }

      // Auto-create backup repository
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
        OpenClaw will automatically back up your configuration to a private GitHub repository. Provide a Personal Access Token with <strong>repo</strong> scope.
      </p>

      <div style={{ background: "var(--surface-1)", border: "1px solid var(--border-subtle)", borderRadius: "12px", padding: "20px", margin: "16px 0" }}>
        <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
          <div>
            <label style={labelStyle}>GitHub Personal Access Token</label>
            <input
              style={inputStyle}
              type="password"
              value={config.githubPat}
              onChange={(e) => { setConfig((c) => ({ ...c, githubPat: e.target.value })); setResult(null); }}
              placeholder="ghp_…"
            />
            <a
              href="https://github.com/settings/tokens/new?scopes=repo&description=OpenClaw+Backup"
              target="_blank"
              rel="noreferrer noopener"
              style={{ fontSize: "11px", color: "var(--accent-primary-hover)", marginTop: "6px", display: "block", textDecoration: "none" }}
            >
              How to create a PAT (repo scope) →
            </a>
          </div>

          <button style={validating ? btnDisabled : btnSecondary} onClick={handleValidate} disabled={validating || !config.githubPat}>
            {validating ? "Validating…" : "Validate & Create Repo"}
          </button>

          {result && (
            <div style={{ fontSize: "13px", color: result.ok ? "var(--accent-success)" : "var(--accent-danger)" }}>
              {result.ok
                ? `✓ Connected as @${result.login ?? "unknown"}. Repository: ${result.repoUrl}`
                : `✗ ${result.error}`}
            </div>
          )}
        </div>
      </div>

      <div style={step.actions}>
        <button style={btnSecondary} onClick={onNext}>Skip (configure later)</button>
        <button style={result?.ok ? btnPrimary : btnSecondary} onClick={onNext}>
          {result?.ok ? "Continue →" : "Continue without Backup →"}
        </button>
      </div>
    </div>
  );
}

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

// ─── Step 6: Installing ───────────────────────────────────────────────────

interface InstallProgress { stage: string; percent: number; message: string; error?: string }

function StepInstalling({ config, onComplete }: { config: WizardConfig; onComplete: () => void }) {
  const [progress, setProgress] = useState<InstallProgress>({ stage: "preparing", percent: 0, message: "Preparing…" });
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) {return;}
    started.current = true;

    // Listen for progress events from main process
    occc.on("occc:install:progress", (...args: unknown[]) => {
      const p = args[0] as InstallProgress;
      setProgress(p);
      if (p.stage === "done") {onComplete();}
      if (p.stage === "error") {setError(p.error ?? "Installation failed.");}
    });

    // Start the installation
    occc.invoke("occc:install:run", {
      llmProvider: config.llmProvider,
      llmApiKey: config.llmApiKey,
      githubPat: config.githubPat,
      githubRepo: config.githubRepo,
      voiceEnabled: config.voiceEnabled,
      gatewayPort: config.gatewayPort,
      bridgePort: config.bridgePort,
    }).catch((err: Error) => {
      setError(err.message);
    });
  }, []);

  return (
    <div style={step.container}>
      <h2 style={step.heading}>Installing…</h2>
      {!error ? (
        <>
          <div style={{ margin: "32px 0 16px" }}>
            <div style={progressTrack}>
              <div style={{ ...progressFill, width: `${progress.percent}%`, transition: "width 500ms var(--ease-out)" }} />
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", marginTop: "8px" }}>
              <p style={{ fontSize: "13px", color: "var(--text-secondary)" }}>{progress.message}</p>
              <span style={{ fontSize: "13px", color: "var(--text-tertiary)" }}>{progress.percent}%</span>
            </div>
          </div>

          <div style={{ display: "flex", justifyContent: "center", marginTop: "16px" }}>
            <div className="spinner" />
          </div>
        </>
      ) : (
        <div style={{ margin: "24px 0" }}>
          <div style={{ ...step.alertBox, borderColor: "var(--accent-danger)", color: "var(--accent-danger)" }}>
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
  progressLine: { position: "absolute", top: "34px", left: "calc(50% / 6 + 32px)", right: "calc(50% / 6 + 32px)", height: "2px", background: "var(--surface-2)", zIndex: 0 },
  progressFill: { height: "100%", background: "var(--accent-primary)", transition: "width 400ms" },
  content: { flex: 1, overflowY: "auto", padding: "0 32px 32px" },
};
const step: Record<string, React.CSSProperties> = {
  container: { maxWidth: "560px", margin: "0 auto", paddingTop: "8px" },
  heading: { fontSize: "20px", fontWeight: 700, color: "var(--text-primary)", margin: "0 0 8px" },
  desc: { fontSize: "13px", color: "var(--text-secondary)", margin: "0", lineHeight: 1.6 },
  center: { display: "flex", flexDirection: "column", alignItems: "center", padding: "40px 0" },
  actions: { display: "flex", gap: "10px", justifyContent: "flex-end", marginTop: "24px" },
  alertBox: { background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.3)", borderRadius: "10px", padding: "14px 16px", fontSize: "13px", color: "var(--text-secondary)" },
};
const progressTrack: React.CSSProperties = { height: "8px", background: "var(--surface-2)", borderRadius: "4px", overflow: "hidden" };
const progressFill: React.CSSProperties = { height: "100%", background: "linear-gradient(90deg, var(--accent-primary), var(--accent-success))", borderRadius: "4px" };
const labelStyle: React.CSSProperties = { display: "block", fontSize: "12px", fontWeight: 600, color: "var(--text-tertiary)", textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: "6px" };
const inputStyle: React.CSSProperties = { width: "100%", background: "rgba(30,30,42,0.8)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: "10px", padding: "10px 14px", fontSize: "14px", color: "var(--text-primary)", outline: "none", fontFamily: "inherit", boxSizing: "border-box" };
const btnPrimary: React.CSSProperties = { background: "linear-gradient(135deg, #6366f1, #4f46e5)", border: "none", borderRadius: "10px", padding: "10px 20px", fontSize: "13px", fontWeight: 600, color: "white", cursor: "pointer", display: "flex", alignItems: "center", gap: "8px" };
const btnSecondary: React.CSSProperties = { background: "var(--surface-1)", border: "1px solid var(--border-default)", borderRadius: "10px", padding: "10px 20px", fontSize: "13px", color: "var(--text-secondary)", cursor: "pointer" };
const btnDisabled: React.CSSProperties = { ...btnPrimary, opacity: 0.5, cursor: "not-allowed" };
