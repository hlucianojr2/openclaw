/**
 * InstallerWizard — Step: Advanced Settings
 *
 * Configures optional low-level settings: port numbers and the voice guide.
 * Defaults work out of the box for most installations; most users can skip.
 */

import React from "react";
import { btnPrimary, labelStyle, inputStyle } from "./installer-styles.js";

export interface AdvancedConfig {
  gatewayPort: number;
  bridgePort: number;
  voiceEnabled: boolean;
}

interface StepAdvancedProps {
  config: AdvancedConfig;
  onChange: (patch: Partial<AdvancedConfig>) => void;
  onNext: () => void;
}

const DEFAULT_GATEWAY_PORT = 18789;
const DEFAULT_BRIDGE_PORT = 18790;

export function StepAdvanced({ config, onChange, onNext }: StepAdvancedProps) {
  const isDefaultPorts =
    config.gatewayPort === DEFAULT_GATEWAY_PORT && config.bridgePort === DEFAULT_BRIDGE_PORT;

  return (
    <div style={container}>
      <h2 style={heading}>Advanced Settings</h2>
      <p style={desc}>
        These defaults work for most installations. Only change them if you have port conflicts or
        specific network requirements.
      </p>

      <div style={card}>
        {/* Gateway Port */}
        <div>
          <label style={labelStyle} htmlFor="gateway-port">Gateway Port</label>
          <p style={fieldDesc}>The port the OpenClaw Gateway listens on for API requests.</p>
          <input
            id="gateway-port"
            style={inputStyle}
            type="number"
            min={1024}
            max={65535}
            value={config.gatewayPort}
            onChange={(e) => {
              const v = Number(e.target.value);
              if (v >= 1024 && v <= 65535) { onChange({ gatewayPort: v }); }
            }}
          />
        </div>

        <div style={divider} />

        {/* Bridge Port */}
        <div>
          <label style={labelStyle} htmlFor="bridge-port">Bridge Port</label>
          <p style={fieldDesc}>The port the OCCC&rarr;Gateway WebSocket bridge uses.</p>
          <input
            id="bridge-port"
            style={inputStyle}
            type="number"
            min={1024}
            max={65535}
            value={config.bridgePort}
            onChange={(e) => {
              const v = Number(e.target.value);
              if (v >= 1024 && v <= 65535) { onChange({ bridgePort: v }); }
            }}
          />
        </div>

        <div style={divider} />

        {/* Voice Guide Toggle */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <label style={labelStyle}>Voice Guide</label>
            <p style={{ ...fieldDesc, margin: 0 }}>
              Narrate wizard steps with text-to-speech during setup.
            </p>
          </div>

          {/* Toggle switch */}
          <button
            onClick={() => onChange({ voiceEnabled: !config.voiceEnabled })}
            aria-label={config.voiceEnabled ? "Disable voice guide" : "Enable voice guide"}
            aria-pressed={config.voiceEnabled}
            style={{
              background: config.voiceEnabled ? "var(--accent-primary)" : "var(--surface-2)",
              border: "none",
              borderRadius: "12px",
              width: "44px",
              height: "24px",
              cursor: "pointer",
              position: "relative",
              transition: "background 200ms",
              flexShrink: 0,
            }}
            title={config.voiceEnabled ? "Disable voice guide" : "Enable voice guide"}
          >
            <span
              style={{
                position: "absolute",
                top: "3px",
                left: config.voiceEnabled ? "22px" : "3px",
                width: "18px",
                height: "18px",
                borderRadius: "50%",
                background: "white",
                transition: "left 200ms",
                display: "block",
              }}
            />
          </button>
        </div>
      </div>

      {/* Reset defaults link — only shown when non-default ports are set */}
      {!isDefaultPorts && (
        <div style={{ textAlign: "center", marginBottom: "8px" }}>
          <button
            style={{
              background: "none",
              border: "none",
              color: "var(--text-muted)",
              fontSize: "12px",
              cursor: "pointer",
              textDecoration: "underline",
            }}
            onClick={() =>
              onChange({ gatewayPort: DEFAULT_GATEWAY_PORT, bridgePort: DEFAULT_BRIDGE_PORT })
            }
          >
            Reset ports to defaults
          </button>
        </div>
      )}

      <div style={actions}>
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
const card: React.CSSProperties = {
  background: "var(--surface-1)",
  border: "1px solid var(--border-subtle)",
  borderRadius: "12px",
  padding: "20px",
  margin: "20px 0",
  display: "flex",
  flexDirection: "column",
  gap: "16px",
};
const divider: React.CSSProperties = {
  height: "1px",
  background: "var(--border-subtle)",
};
const fieldDesc: React.CSSProperties = {
  fontSize: "12px",
  color: "var(--text-tertiary)",
  margin: "2px 0 6px",
};
const actions: React.CSSProperties = {
  display: "flex",
  gap: "10px",
  justifyContent: "flex-end",
  marginTop: "24px",
};
// labelStyle, inputStyle, and btnPrimary are imported from installer-styles.ts
