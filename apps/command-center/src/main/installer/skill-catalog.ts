/**
 * Skill Catalog — static registry of installable skills for wizard Step 6.
 *
 * Mirrors the governance rules from the Implementation Plan Phase 5:
 *   auto-approved  → install immediately
 *   user-ack       → user must acknowledge risk before install
 *   admin-review   → elevated session + AI scan required
 *   blocked        → never permitted in OCCC-managed installs
 */

import type { SkillCatalogEntry } from "../../shared/ipc-types.js";

/** Full catalog of skills available during the install wizard. */
export const SKILL_CATALOG: SkillCatalogEntry[] = [
  // ─── Auto-Approved (low risk, recommended defaults) ─────────────────────

  {
    id: "healthcheck",
    name: "Health Check",
    description: "Monitors gateway and container health, reports status on demand.",
    riskLevel: "low",
    approvalLevel: "auto-approved",
    recommended: true,
    requiresApiKey: false,
    category: "monitoring",
  },
  {
    id: "session-logs",
    name: "Session Logs",
    description: "View conversation history and agent session transcripts.",
    riskLevel: "low",
    approvalLevel: "auto-approved",
    recommended: true,
    requiresApiKey: false,
    category: "monitoring",
  },
  {
    id: "model-usage",
    name: "Model Usage",
    description: "Track token consumption and cost across AI providers.",
    riskLevel: "low",
    approvalLevel: "auto-approved",
    recommended: true,
    requiresApiKey: false,
    category: "analytics",
  },
  {
    id: "summarize",
    name: "Summarize",
    description: "Summarize long documents, threads, or web pages.",
    riskLevel: "low",
    approvalLevel: "auto-approved",
    recommended: true,
    requiresApiKey: false,
    category: "productivity",
  },
  {
    id: "canvas",
    name: "Canvas",
    description: "Interactive canvas for diagrams, notes, and visual collaboration.",
    riskLevel: "low",
    approvalLevel: "auto-approved",
    recommended: false,
    requiresApiKey: false,
    category: "productivity",
  },
  {
    id: "weather",
    name: "Weather",
    description: "Get current weather and forecasts for any location.",
    riskLevel: "low",
    approvalLevel: "auto-approved",
    recommended: false,
    requiresApiKey: false,
    category: "utilities",
  },

  // ─── User Acknowledgement Required ──────────────────────────────────────

  {
    id: "github",
    name: "GitHub",
    description: "Read and write to GitHub repositories, manage issues and PRs.",
    riskLevel: "medium",
    approvalLevel: "user-ack",
    recommended: false,
    requiresApiKey: true,
    apiKeyLabel: "GitHub Personal Access Token",
    officialLink: "https://github.com/settings/tokens",
    category: "development",
  },
  {
    id: "notion",
    name: "Notion",
    description: "Read and write Notion pages, databases, and workspaces.",
    riskLevel: "medium",
    approvalLevel: "user-ack",
    recommended: false,
    requiresApiKey: true,
    apiKeyLabel: "Notion Integration Token",
    officialLink: "https://www.notion.so/my-integrations",
    category: "productivity",
  },
  {
    id: "obsidian",
    name: "Obsidian",
    description: "Access and edit Obsidian vaults on the local filesystem.",
    riskLevel: "medium",
    approvalLevel: "user-ack",
    recommended: false,
    requiresApiKey: false,
    category: "productivity",
  },
  {
    id: "trello",
    name: "Trello",
    description: "Manage Trello boards, lists, and cards.",
    riskLevel: "medium",
    approvalLevel: "user-ack",
    recommended: false,
    requiresApiKey: true,
    apiKeyLabel: "Trello API Key",
    officialLink: "https://trello.com/app-key",
    category: "productivity",
  },
  {
    id: "slack",
    name: "Slack (Skill)",
    description: "Send and read messages in Slack workspaces via the API.",
    riskLevel: "medium",
    approvalLevel: "user-ack",
    recommended: false,
    requiresApiKey: true,
    apiKeyLabel: "Slack Bot Token",
    officialLink: "https://api.slack.com/apps",
    category: "communication",
  },
  {
    id: "discord",
    name: "Discord (Skill)",
    description: "Interact with Discord servers and channels via the API.",
    riskLevel: "medium",
    approvalLevel: "user-ack",
    recommended: false,
    requiresApiKey: true,
    apiKeyLabel: "Discord Bot Token",
    officialLink: "https://discord.com/developers/applications",
    category: "communication",
  },

  // ─── Admin Approval + AI Review Required ────────────────────────────────

  {
    id: "coding-agent",
    name: "Coding Agent",
    description: "Fully autonomous coding agent with filesystem and terminal access.",
    riskLevel: "high",
    approvalLevel: "admin-review",
    recommended: false,
    requiresApiKey: false,
    category: "development",
  },
  {
    id: "tmux",
    name: "Tmux Terminal",
    description: "Execute shell commands and manage terminal sessions.",
    riskLevel: "high",
    approvalLevel: "admin-review",
    recommended: false,
    requiresApiKey: false,
    category: "system",
  },
  {
    id: "skill-creator",
    name: "Skill Creator",
    description: "Create and publish new skills. Requires thorough security review.",
    riskLevel: "high",
    approvalLevel: "admin-review",
    recommended: false,
    requiresApiKey: false,
    category: "development",
  },
];

/**
 * Returns skills filtered by approval level.
 */
export function getSkillsByApprovalLevel(
  level: SkillCatalogEntry["approvalLevel"],
): SkillCatalogEntry[] {
  return SKILL_CATALOG.filter((s) => s.approvalLevel === level);
}

/**
 * Returns the default recommended skills for first-time installation.
 */
export function getRecommendedSkills(): SkillCatalogEntry[] {
  return SKILL_CATALOG.filter((s) => s.recommended);
}

/**
 * Look up a single skill by id. Returns undefined if not found.
 */
export function findSkillById(id: string): SkillCatalogEntry | undefined {
  return SKILL_CATALOG.find((s) => s.id === id);
}
