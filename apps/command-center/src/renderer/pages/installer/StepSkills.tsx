/**
 * InstallerWizard — Step: Starter Skills
 *
 * Lets the user choose which default skills to enable during installation.
 * Selections are passed back to WizardConfig.selectedSkills.
 * Full management available post-install in the Skills panel.
 */

import React from "react";
import { btnPrimary, btnSecondary } from "./installer-styles.js";

interface StepSkillsProps {
  selectedSkills: string[];
  onToggle: (skillId: string) => void;
  onNext: () => void;
}

interface StarterSkill {
  id: string;
  name: string;
  description: string;
  icon: string;
  recommended: boolean;
}

const STARTER_SKILLS: StarterSkill[] = [
  {
    id: "memory-core",
    name: "Memory Core",
    description: "Persistent memory across sessions. Agents remember context between conversations.",
    icon: "🧠",
    recommended: true,
  },
  {
    id: "brave-search",
    name: "Web Search",
    description: "Real-time web search via Brave Search API. Agents can look up current information.",
    icon: "🔍",
    recommended: true,
  },
  {
    id: "llm-task",
    name: "LLM Tasks",
    description: "Delegate subtasks to secondary LLM calls for complex reasoning chains.",
    icon: "⚡",
    recommended: true,
  },
  {
    id: "open-prose",
    name: "Open Prose",
    description: "Document creation: drafting, editing, and formatting long-form content.",
    icon: "📝",
    recommended: false,
  },
  {
    id: "device-pair",
    name: "Device Pair",
    description: "Pair and manage connected devices in your OpenClaw network.",
    icon: "🔗",
    recommended: false,
  },
  {
    id: "phone-control",
    name: "Phone Control",
    description: "Control Android/iOS devices for automation and notifications.",
    icon: "📱",
    recommended: false,
  },
];

export function StepSkills({ selectedSkills, onToggle, onNext }: StepSkillsProps) {
  return (
    <div style={container}>
      <h2 style={heading}>Starter Skills</h2>
      <p style={desc}>
        Choose which skills to enable from the start. You can install or remove skills at any time
        from the Skills panel.
      </p>

      <div style={{ display: "flex", flexDirection: "column", gap: "10px", margin: "20px 0" }}>
        {STARTER_SKILLS.map((skill) => {
          const selected = selectedSkills.includes(skill.id);
          const toggle = () => onToggle(skill.id);
          return (
            <div
              key={skill.id}
              role="button"
              tabIndex={0}
              aria-pressed={selected}
              onClick={toggle}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  toggle();
                }
              }}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "14px",
                padding: "14px 16px",
                background: selected ? "var(--accent-primary-glow)" : "var(--surface-1)",
                border: `1px solid ${selected ? "var(--accent-primary)" : "var(--border-subtle)"}`,
                borderRadius: "12px",
                cursor: "pointer",
                transition: "all 200ms",
              }}
            >
              <span style={{ fontSize: "24px", flexShrink: 0 }}>{skill.icon}</span>
              <div style={{ flex: 1 }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <span style={{ fontSize: "13px", fontWeight: 600, color: "var(--text-primary)" }}>
                    {skill.name}
                  </span>
                  {skill.recommended && (
                    <span
                      style={{
                        fontSize: "10px",
                        fontWeight: 600,
                        background: "var(--accent-primary-glow)",
                        color: "var(--accent-primary)",
                        border: "1px solid var(--accent-primary)",
                        borderRadius: "4px",
                        padding: "1px 6px",
                      }}
                    >
                      Recommended
                    </span>
                  )}
                </div>
                <div
                  style={{
                    fontSize: "12px",
                    color: "var(--text-secondary)",
                    marginTop: "3px",
                    lineHeight: 1.4,
                  }}
                >
                  {skill.description}
                </div>
              </div>

              {/* Circular checkbox */}
              <div
                style={{
                  width: "20px",
                  height: "20px",
                  borderRadius: "50%",
                  border: `2px solid ${selected ? "var(--accent-primary)" : "var(--border-default)"}`,
                  background: selected ? "var(--accent-primary)" : "transparent",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  flexShrink: 0,
                  fontSize: "11px",
                  color: "white",
                  transition: "all 200ms",
                }}
              >
                {selected ? "✓" : ""}
              </div>
            </div>
          );
        })}
      </div>

      <p style={{ fontSize: "12px", color: "var(--text-muted)", textAlign: "center" }}>
        {selectedSkills.length} skill{selectedSkills.length !== 1 ? "s" : ""} selected
      </p>

      <div style={actions}>
        <button style={btnSecondary} onClick={onNext}>
          Skip
        </button>
        <button style={btnPrimary} onClick={onNext}>
          Continue →
        </button>
      </div>
    </div>
  );
}

// ─── Styles ───────────────────────────────────────────────────────────────

const container: React.CSSProperties = {
  maxWidth: "560px",
  margin: "0 auto",
  paddingTop: "8px",
};
const heading: React.CSSProperties = {
  fontSize: "20px",
  fontWeight: 700,
  color: "var(--text-primary)",
  margin: "0 0 8px",
};
const desc: React.CSSProperties = {
  fontSize: "13px",
  color: "var(--text-secondary)",
  margin: "0",
  lineHeight: 1.6,
};
const actions: React.CSSProperties = {
  display: "flex",
  gap: "10px",
  justifyContent: "flex-end",
  marginTop: "24px",
};
// btnPrimary and btnSecondary are imported from installer-styles.ts
