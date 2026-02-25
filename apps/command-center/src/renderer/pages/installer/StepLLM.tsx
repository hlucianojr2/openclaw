/**
 * InstallerWizard — Step: AI Provider
 *
 * Lets the user pick their preferred language model and enter an API key.
 * LLM_OPTIONS is exported so the Review step can look up the label for display.
 */

import React from "react";
import type { WizardConfig, LLMProvider } from "./installer-types.js";
import { step, btnPrimary, btnSecondary, labelStyle, inputStyle } from "./installer-styles.js";

interface StepLLMProps {
  config: WizardConfig;
  setConfig: React.Dispatch<React.SetStateAction<WizardConfig>>;
  onNext: () => void;
}

export interface LLMOption {
  id: LLMProvider;
  label: string;
  desc: string;
  icon: string;
  keyLabel: string;
  keyPlaceholder: string;
  keyUrl: string;
}

export const LLM_OPTIONS: LLMOption[] = [
  {
    id: "anthropic",
    label: "Anthropic Claude",
    desc: "Best reasoning & safety. Recommended.",
    icon: "🤖",
    keyLabel: "Anthropic API Key",
    keyPlaceholder: "sk-ant-…",
    keyUrl: "https://console.anthropic.com/settings/keys",
  },
  {
    id: "google-gemini",
    label: "Google Gemini",
    desc: "Powerful multimodal model from Google.",
    icon: "✦",
    keyLabel: "Gemini API Key",
    keyPlaceholder: "AIza…",
    keyUrl: "https://aistudio.google.com/app/apikey",
  },
  {
    id: "openai",
    label: "OpenAI",
    desc: "GPT-4o and family of models.",
    icon: "◎",
    keyLabel: "OpenAI API Key",
    keyPlaceholder: "sk-…",
    keyUrl: "https://platform.openai.com/api-keys",
  },
  {
    id: "ollama",
    label: "Ollama (Local)",
    desc: "Fully local, no API key required.",
    icon: "🦙",
    keyLabel: "",
    keyPlaceholder: "",
    keyUrl: "",
  },
];

export function StepLLM({ config, setConfig, onNext }: StepLLMProps) {
  const selected = LLM_OPTIONS.find((o) => o.id === config.llmProvider)!;

  return (
    <div style={step.container}>
      <h2 style={step.heading}>AI Provider</h2>
      <p style={step.desc}>
        Choose your preferred language model. You can change this later in Configuration.
      </p>

      {/* Provider selection grid — keyboard accessible */}
      <div
        style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px", margin: "20px 0 16px" }}
      >
        {LLM_OPTIONS.map((opt) => {
          const isSelected = config.llmProvider === opt.id;
          const select = () => setConfig((c) => ({ ...c, llmProvider: opt.id, llmApiKey: "" }));
          return (
            <div
              key={opt.id}
              role="button"
              tabIndex={0}
              onClick={select}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  select();
                }
              }}
              aria-pressed={isSelected}
              style={{
                padding: "14px 16px",
                background: isSelected ? "var(--accent-primary-glow)" : "var(--surface-1)",
                border: `1px solid ${isSelected ? "var(--accent-primary)" : "var(--border-subtle)"}`,
                borderRadius: "12px",
                cursor: "pointer",
                transition: "all 200ms",
              }}
            >
              <span style={{ fontSize: "20px" }}>{opt.icon}</span>
              <div style={{ fontWeight: 600, fontSize: "13px", marginTop: "6px" }}>{opt.label}</div>
              <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "3px" }}>
                {opt.desc}
              </div>
            </div>
          );
        })}
      </div>

      {selected.keyLabel && (
        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
          <label style={labelStyle} htmlFor="llm-api-key">
            {selected.keyLabel}
          </label>
          <input
            id="llm-api-key"
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
              style={{
                fontSize: "12px",
                color: "var(--accent-primary-hover)",
                textDecoration: "none",
              }}
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
