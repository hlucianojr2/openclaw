/**
 * Skill AI Reviewer — runs a security-focused LLM review of a skill scan.
 *
 * Uses @anthropic-ai/sdk via dynamic import so the dependency is optional.
 * Returns null if the SDK is unavailable or the API key is not set.
 * The caller (SkillGovernance) treats null as "human-only review required".
 */

import type { AiReviewResult, SkillScanSummary } from "../../shared/ipc-types.js";

// Minimal structural types for the Anthropic SDK (avoids a static hard dependency)
interface AnthropicMessages {
  create(params: {
    model: string;
    max_tokens: number;
    messages: { role: string; content: string }[];
  }): Promise<{ content?: { type: string; text?: string }[] }>;
}

interface AnthropicClient {
  messages: AnthropicMessages;
}

const HAIKU_MODEL = "claude-haiku-4-5-20251001";

export class SkillAiReviewer {
  constructor(private readonly apiKey?: string) {}

  /**
   * Review a skill scan result and produce a recommendation.
   * Returns null if AI review is unavailable (no key, SDK absent, network error).
   */
  async review(
    skillId: string,
    skillName: string,
    scan: SkillScanSummary,
  ): Promise<AiReviewResult | null> {
    if (!this.apiKey) { return null; }

    try {
      // Dynamic import so builds without @anthropic-ai/sdk still work
      const mod = await import("@anthropic-ai/sdk") as {
        Anthropic: new (opts: { apiKey: string }) => AnthropicClient;
      };
      const client = new mod.Anthropic({ apiKey: this.apiKey });
      return await this.runReview(client, skillId, skillName, scan);
    } catch {
      return null;
    }
  }

  private async runReview(
    client: AnthropicClient,
    skillId: string,
    skillName: string,
    scan: SkillScanSummary,
  ): Promise<AiReviewResult | null> {
    try {
      const response = await client.messages.create({
        model: HAIKU_MODEL,
        max_tokens: 512,
        messages: [{ role: "user", content: buildPrompt(skillId, skillName, scan) }],
      });
      const text = response.content?.[0]?.type === "text" ? (response.content[0].text ?? "") : "";
      return parseResponse(text);
    } catch {
      return null;
    }
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function buildPrompt(skillId: string, skillName: string, scan: SkillScanSummary): string {
  const criticalList = scan.findings
    .filter((f) => f.severity === "critical")
    .map((f) => `- ${f.ruleId}: ${f.message} (${f.file}:${f.line})`)
    .join("\n") || "(none)";

  const warnList = scan.findings
    .filter((f) => f.severity === "warn")
    .map((f) => `- ${f.ruleId}: ${f.message}`)
    .join("\n") || "(none)";

  return `You are a security reviewer for OpenClaw, an AI agent platform.
Review the skill "${skillName}" (id: ${skillId}) based on static scan results.

Scanned files: ${scan.scannedFiles}
Critical findings: ${scan.critical}
Warning findings: ${scan.warn}
Info findings: ${scan.info}

Critical issues:
${criticalList}

Warnings:
${warnList}

Respond with JSON only (no markdown code blocks):
{
  "recommendation": "approve" | "reject" | "review",
  "summary": "<one sentence>",
  "concerns": ["<concern>", ...],
  "confidence": <0.0-1.0>
}`;
}

function parseResponse(text: string): AiReviewResult | null {
  try {
    // Strip markdown code fences if the model includes them despite the instruction
    const cleaned = text.trim()
      .replace(/^```[a-z]*\n?/i, "")
      .replace(/\n?```$/i, "")
      .trim();
    const json = JSON.parse(cleaned) as {
      recommendation: unknown;
      summary?: unknown;
      concerns?: unknown;
      confidence?: unknown;
    };
    const rec = json.recommendation;
    if (rec !== "approve" && rec !== "reject" && rec !== "review") { return null; }
    return {
      recommendation: rec,
      summary: typeof json.summary === "string" ? json.summary : "",
      concerns: Array.isArray(json.concerns) ? json.concerns.map(String) : [],
      confidence: typeof json.confidence === "number"
        ? Math.min(1, Math.max(0, json.confidence))
        : 0.5,
      provider: "anthropic",
    };
  } catch {
    return null;
  }
}
