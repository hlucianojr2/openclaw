/**
 * Channel Catalog — static registry of messaging channels for wizard Step 7.
 *
 * Includes both built-in channels (shipped with OpenClaw core) and
 * extension-based channels (installed from extensions/).
 *
 * The `requiredFields` list drives the wizard's channel config form; the
 * renderer collects values and POSTs them back via INSTALL_CHANNEL_VALIDATE
 * before they are written into the gateway config.
 */

import type { ChannelCatalogEntry } from "../../shared/ipc-types.js";

/** Full catalog of channels available during the install wizard. */
export const CHANNEL_CATALOG: ChannelCatalogEntry[] = [
  // ─── Messaging (consumer) ────────────────────────────────────────────────

  {
    id: "telegram",
    name: "Telegram",
    description: "Connect via a Telegram Bot. Most popular choice — works on all platforms.",
    category: "messaging",
    recommended: true,
    requiresAppSetup: true,
    setupGuideUrl: "https://docs.openclaw.ai/channels/telegram",
    builtin: false,
    requiredFields: [
      {
        key: "botToken",
        label: "Bot Token",
        type: "password",
        description: "Create a bot with @BotFather and paste the token here.",
        required: true,
        placeholder: "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw",
      },
    ],
  },
  {
    id: "whatsapp",
    name: "WhatsApp",
    description: "Connect via WhatsApp Web protocol (no Business API needed).",
    category: "messaging",
    recommended: false,
    requiresAppSetup: true,
    setupGuideUrl: "https://docs.openclaw.ai/channels/whatsapp",
    builtin: true,
    requiredFields: [
      // WhatsApp uses a QR-code scan flow — no pre-config fields needed
    ],
  },
  {
    id: "signal",
    name: "Signal",
    description: "Connect via Signal — privacy-first end-to-end encrypted messaging.",
    category: "messaging",
    recommended: false,
    requiresAppSetup: true,
    setupGuideUrl: "https://docs.openclaw.ai/channels/signal",
    builtin: false,
    requiredFields: [
      {
        key: "phoneNumber",
        label: "Phone Number",
        type: "text",
        description: "The phone number registered with Signal (E.164 format).",
        required: true,
        placeholder: "+15551234567",
      },
    ],
  },
  {
    id: "imessage",
    name: "iMessage",
    description: "Connect via iMessage (macOS only — requires Contacts access).",
    category: "messaging",
    recommended: false,
    requiresAppSetup: true,
    setupGuideUrl: "https://docs.openclaw.ai/channels/imessage",
    builtin: true,
    requiredFields: [],
  },

  // ─── Team Chat ───────────────────────────────────────────────────────────

  {
    id: "discord",
    name: "Discord",
    description: "Connect to Discord servers and DMs via a Discord Bot.",
    category: "team-chat",
    recommended: false,
    requiresAppSetup: true,
    setupGuideUrl: "https://docs.openclaw.ai/channels/discord",
    builtin: false,
    requiredFields: [
      {
        key: "botToken",
        label: "Bot Token",
        type: "password",
        description: "Create a bot at discord.com/developers and paste the token.",
        required: true,
        placeholder: "MTk4NjIyNDgzNDcxOTI1MjQ4.Cl2FDg.zbG4…",
      },
    ],
  },
  {
    id: "slack",
    name: "Slack",
    description: "Connect to Slack workspaces via a Slack App.",
    category: "team-chat",
    recommended: false,
    requiresAppSetup: true,
    setupGuideUrl: "https://docs.openclaw.ai/channels/slack",
    builtin: false,
    requiredFields: [
      {
        key: "botToken",
        label: "Bot OAuth Token",
        type: "password",
        description: "xoxb- token from your Slack App's OAuth & Permissions page.",
        required: true,
        placeholder: "xoxb-…",
      },
      {
        key: "appToken",
        label: "App-Level Token",
        type: "password",
        description: "xapp- token with connections:write scope (for Socket Mode).",
        required: true,
        placeholder: "xapp-…",
      },
    ],
  },
  {
    id: "msteams",
    name: "Microsoft Teams",
    description: "Connect via a Microsoft Teams Bot Framework integration.",
    category: "team-chat",
    recommended: false,
    requiresAppSetup: true,
    setupGuideUrl: "https://docs.openclaw.ai/channels/msteams",
    builtin: false,
    requiredFields: [
      {
        key: "appId",
        label: "App ID",
        type: "text",
        description: "Azure Bot registration Application (client) ID.",
        required: true,
        placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      },
      {
        key: "appPassword",
        label: "App Password",
        type: "password",
        description: "Azure Bot registration client secret.",
        required: true,
        placeholder: "",
      },
    ],
  },
  {
    id: "matrix",
    name: "Matrix",
    description: "Connect to any Matrix homeserver (Element, Beeper, etc.).",
    category: "team-chat",
    recommended: false,
    requiresAppSetup: true,
    setupGuideUrl: "https://docs.openclaw.ai/channels/matrix",
    builtin: false,
    requiredFields: [
      {
        key: "homeserverUrl",
        label: "Homeserver URL",
        type: "text",
        description: "Your Matrix homeserver URL, e.g. https://matrix.org",
        required: true,
        placeholder: "https://matrix.org",
      },
      {
        key: "accessToken",
        label: "Access Token",
        type: "password",
        description: "Access token for the bot account on this homeserver.",
        required: true,
        placeholder: "",
      },
      {
        key: "userId",
        label: "Bot User ID",
        type: "text",
        description: "Full Matrix user ID of the bot, e.g. @mybot:matrix.org",
        required: true,
        placeholder: "@mybot:matrix.org",
      },
    ],
  },

  // ─── Social / Other ──────────────────────────────────────────────────────

  {
    id: "irc",
    name: "IRC",
    description: "Connect to IRC networks via a simple bot.",
    category: "social",
    recommended: false,
    requiresAppSetup: true,
    setupGuideUrl: "https://docs.openclaw.ai/channels/irc",
    builtin: false,
    requiredFields: [
      {
        key: "server",
        label: "Server",
        type: "text",
        description: "IRC server hostname, e.g. irc.libera.chat",
        required: true,
        placeholder: "irc.libera.chat",
      },
      {
        key: "port",
        label: "Port",
        type: "number",
        description: "IRC server port (default 6667 or 6697 for TLS).",
        required: false,
        placeholder: "6697",
      },
      {
        key: "nick",
        label: "Nickname",
        type: "text",
        description: "IRC bot nickname.",
        required: true,
        placeholder: "occc-bot",
      },
      {
        key: "password",
        label: "NickServ Password",
        type: "password",
        description: "NickServ password (optional, leave blank if not registered).",
        required: false,
        placeholder: "",
      },
    ],
  },
];

/**
 * Returns channels filtered by category.
 */
export function getChannelsByCategory(
  category: ChannelCatalogEntry["category"],
): ChannelCatalogEntry[] {
  return CHANNEL_CATALOG.filter((c) => c.category === category);
}

/**
 * Returns the default recommended channels for first-time installation.
 */
export function getRecommendedChannels(): ChannelCatalogEntry[] {
  return CHANNEL_CATALOG.filter((c) => c.recommended);
}

/**
 * Look up a single channel by id. Returns undefined if not found.
 */
export function findChannelById(id: string): ChannelCatalogEntry | undefined {
  return CHANNEL_CATALOG.find((c) => c.id === id);
}

/**
 * Validate a channel config object against the channel's requiredFields.
 * Returns { valid: true } or { valid: false, error: "<message>" }.
 */
export function validateChannelConfig(
  channelId: string,
  config: Record<string, string>,
): { valid: boolean; error?: string } {
  const channel = findChannelById(channelId);
  if (!channel) {
    return { valid: false, error: `Unknown channel: ${channelId}` };
  }

  for (const field of channel.requiredFields) {
    if (!field.required) { continue; }
    const value = config[field.key];
    if (value === undefined || value === null || value.trim() === "") {
      return { valid: false, error: `Missing required field: ${field.label}` };
    }
  }

  return { valid: true };
}
