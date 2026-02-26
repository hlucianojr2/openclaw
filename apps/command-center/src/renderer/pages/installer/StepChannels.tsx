/**
 * InstallerWizard — Step: Messaging Channels
 *
 * Lets the user pick which messaging channels to activate. Channels need
 * tokens/credentials that can be configured in the Config Center after setup.
 * The selections here determine which channel containers are provisioned.
 */

import React from "react";
import { btnPrimary, btnSecondary } from "./installer-styles.js";

interface StepChannelsProps {
  enabledChannels: string[];
  onToggle: (channelId: string) => void;
  onNext: () => void;
}

interface ChannelOption {
  id: string;
  name: string;
  description: string;
  icon: string;
  tag?: string;
}

const CHANNEL_OPTIONS: ChannelOption[] = [
  {
    id: "telegram",
    name: "Telegram",
    description: "Connect a Telegram Bot to send and receive messages.",
    icon: "✈",
    tag: "Popular",
  },
  {
    id: "discord",
    name: "Discord",
    description: "Interact via a Discord server bot — channels and DMs.",
    icon: "◈",
    tag: "Popular",
  },
  {
    id: "signal",
    name: "Signal",
    description: "Private, encrypted messaging via the Signal protocol.",
    icon: "🔒",
  },
  {
    id: "whatsapp",
    name: "WhatsApp",
    description: "Connect via WhatsApp Business API or WhatsApp Web.",
    icon: "💬",
  },
  {
    id: "slack",
    name: "Slack",
    description: "Integrate with a Slack workspace via a Bot token.",
    icon: "⚡",
  },
  {
    id: "imessage",
    name: "iMessage",
    description: "Receive and reply to iMessages (macOS only).",
    icon: "🍎",
    tag: "macOS",
  },
  {
    id: "web",
    name: "Web Chat",
    description: "Embeddable web chat widget for browser-based access.",
    icon: "🌐",
  },
  {
    id: "msteams",
    name: "Microsoft Teams",
    description: "OpenClaw bot for Microsoft Teams channels and chats.",
    icon: "📊",
  },
];

export function StepChannels({ enabledChannels, onToggle, onNext }: StepChannelsProps) {
  return (
    <div style={container}>
      <h2 style={heading}>Messaging Channels</h2>
      <p style={desc}>
        Choose which channels to activate. Tokens and credentials are configured in the Config
        Center after setup is complete.
      </p>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "10px",
          margin: "20px 0",
        }}
      >
        {CHANNEL_OPTIONS.map((ch) => {
          const enabled = enabledChannels.includes(ch.id);
          const toggle = () => onToggle(ch.id);
          return (
            <div
              key={ch.id}
              role="button"
              tabIndex={0}
              aria-pressed={enabled}
              onClick={toggle}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  toggle();
                }
              }}
              style={{
                padding: "14px 16px",
                background: enabled ? "var(--accent-primary-glow)" : "var(--surface-1)",
                border: `1px solid ${enabled ? "var(--accent-primary)" : "var(--border-subtle)"}`,
                borderRadius: "12px",
                cursor: "pointer",
                transition: "all 200ms",
                position: "relative",
              }}
            >
              {ch.tag && (
                <span
                  style={{
                    position: "absolute",
                    top: "8px",
                    right: "8px",
                    fontSize: "9px",
                    fontWeight: 700,
                    color: "var(--text-muted)",
                    background: "var(--surface-2)",
                    borderRadius: "4px",
                    padding: "2px 5px",
                    textTransform: "uppercase",
                    letterSpacing: "0.05em",
                  }}
                >
                  {ch.tag}
                </span>
              )}

              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "10px",
                  marginBottom: "6px",
                }}
              >
                <span style={{ fontSize: "20px" }}>{ch.icon}</span>
                <span
                  style={{ fontSize: "13px", fontWeight: 600, color: "var(--text-primary)" }}
                >
                  {ch.name}
                </span>
              </div>

              <div
                style={{ fontSize: "11px", color: "var(--text-secondary)", lineHeight: 1.4 }}
              >
                {ch.description}
              </div>

              {/* Checkbox row */}
              <div
                style={{
                  marginTop: "10px",
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  fontSize: "11px",
                  fontWeight: 600,
                  color: enabled ? "var(--accent-primary)" : "var(--text-muted)",
                }}
              >
                <div
                  style={{
                    width: "14px",
                    height: "14px",
                    borderRadius: "3px",
                    border: `2px solid ${enabled ? "var(--accent-primary)" : "var(--border-default)"}`,
                    background: enabled ? "var(--accent-primary)" : "transparent",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontSize: "9px",
                    color: "white",
                    transition: "all 200ms",
                    flexShrink: 0,
                  }}
                >
                  {enabled ? "✓" : ""}
                </div>
                {enabled ? "Enabled" : "Disabled"}
              </div>
            </div>
          );
        })}
      </div>

      <p style={{ fontSize: "12px", color: "var(--text-muted)", textAlign: "center" }}>
        {enabledChannels.length} channel{enabledChannels.length !== 1 ? "s" : ""} selected
        &mdash; tokens configured after setup
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
