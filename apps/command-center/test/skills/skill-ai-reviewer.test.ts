/**
 * Tests for SkillAiReviewer — null fallbacks and response parsing.
 *
 * Uses a hoisted vi.mock for @anthropic-ai/sdk with a shared mock create
 * function so tests can control per-call behavior cleanly.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { SkillScanSummary } from "../../src/shared/ipc-types.js";

// ─── Mock @anthropic-ai/sdk ───────────────────────────────────────────────────

const mockCreate = vi.fn();

vi.mock("@anthropic-ai/sdk", () => ({
  Anthropic: class {
    messages = { create: mockCreate };
  },
}));

// ─── Test data ────────────────────────────────────────────────────────────────

const emptyScan: SkillScanSummary = {
  scannedFiles: 5,
  critical: 0,
  warn: 0,
  info: 0,
  findings: [],
};

describe("SkillAiReviewer", () => {
  let SkillAiReviewer: typeof import("../../src/main/skills/skill-ai-reviewer.js").SkillAiReviewer;

  beforeEach(async () => {
    vi.clearAllMocks();
    const mod = await import("../../src/main/skills/skill-ai-reviewer.js");
    SkillAiReviewer = mod.SkillAiReviewer;
  });

  it("returns null when no API key is set", async () => {
    const reviewer = new SkillAiReviewer(undefined);
    const result = await reviewer.review("healthcheck", "Health Check", emptyScan);
    expect(result).toBeNull();
    expect(mockCreate).not.toHaveBeenCalled();
  });

  it("returns null when messages.create throws", async () => {
    mockCreate.mockRejectedValue(new Error("Network error"));
    const reviewer = new SkillAiReviewer("sk-ant-fake");
    const result = await reviewer.review("healthcheck", "Health Check", emptyScan);
    expect(result).toBeNull();
  });

  it("returns null when Anthropic API returns non-JSON text", async () => {
    mockCreate.mockResolvedValue({
      content: [{ type: "text", text: "I cannot provide a review at this time." }],
    });
    const reviewer = new SkillAiReviewer("sk-ant-fake");
    const result = await reviewer.review("healthcheck", "Health Check", emptyScan);
    expect(result).toBeNull();
  });

  it("returns null when recommendation value is unrecognized", async () => {
    mockCreate.mockResolvedValue({
      content: [{ type: "text", text: JSON.stringify({ recommendation: "maybe", summary: "x", concerns: [], confidence: 0.5 }) }],
    });
    const reviewer = new SkillAiReviewer("sk-ant-fake");
    const result = await reviewer.review("healthcheck", "Health Check", emptyScan);
    expect(result).toBeNull();
  });

  it("parses a well-formed approve response", async () => {
    mockCreate.mockResolvedValue({
      content: [{ type: "text", text: JSON.stringify({
        recommendation: "approve",
        summary: "Skill appears safe with no critical findings.",
        concerns: [],
        confidence: 0.9,
      }) }],
    });
    const reviewer = new SkillAiReviewer("sk-ant-fake");
    const result = await reviewer.review("healthcheck", "Health Check", emptyScan);

    expect(result).not.toBeNull();
    expect(result?.recommendation).toBe("approve");
    expect(result?.confidence).toBe(0.9);
    expect(result?.provider).toBe("anthropic");
    expect(result?.concerns).toHaveLength(0);
    expect(result?.summary).toBe("Skill appears safe with no critical findings.");
  });

  it("parses a reject response with concerns", async () => {
    mockCreate.mockResolvedValue({
      content: [{ type: "text", text: JSON.stringify({
        recommendation: "reject",
        summary: "Critical security issues found.",
        concerns: ["Reads /etc/passwd", "Exfiltrates data"],
        confidence: 0.95,
      }) }],
    });
    const reviewer = new SkillAiReviewer("sk-ant-fake");
    const result = await reviewer.review("bad-skill", "Bad Skill", { ...emptyScan, critical: 2 });

    expect(result?.recommendation).toBe("reject");
    expect(result?.concerns).toHaveLength(2);
    expect(result?.concerns[0]).toBe("Reads /etc/passwd");
  });

  it("parses a review response", async () => {
    mockCreate.mockResolvedValue({
      content: [{ type: "text", text: JSON.stringify({
        recommendation: "review",
        summary: "Uncertain — manual inspection needed.",
        concerns: ["Uses eval"],
        confidence: 0.6,
      }) }],
    });
    const reviewer = new SkillAiReviewer("sk-ant-fake");
    const result = await reviewer.review("risky-skill", "Risky Skill", emptyScan);
    expect(result?.recommendation).toBe("review");
  });

  it("clamps confidence above 1 down to 1", async () => {
    mockCreate.mockResolvedValue({
      content: [{ type: "text", text: JSON.stringify({
        recommendation: "review",
        summary: "Uncertain.",
        concerns: [],
        confidence: 1.5,
      }) }],
    });
    const reviewer = new SkillAiReviewer("sk-ant-fake");
    const result = await reviewer.review("x", "X", emptyScan);
    expect(result?.confidence).toBe(1);
  });

  it("clamps confidence below 0 up to 0", async () => {
    mockCreate.mockResolvedValue({
      content: [{ type: "text", text: JSON.stringify({
        recommendation: "approve",
        summary: "Fine.",
        concerns: [],
        confidence: -0.3,
      }) }],
    });
    const reviewer = new SkillAiReviewer("sk-ant-fake");
    const result = await reviewer.review("x", "X", emptyScan);
    expect(result?.confidence).toBe(0);
  });

  it("strips markdown code fences from model response", async () => {
    const json = JSON.stringify({
      recommendation: "approve",
      summary: "Clean.",
      concerns: [],
      confidence: 0.8,
    });
    mockCreate.mockResolvedValue({
      content: [{ type: "text", text: "```json\n" + json + "\n```" }],
    });
    const reviewer = new SkillAiReviewer("sk-ant-fake");
    const result = await reviewer.review("x", "X", emptyScan);
    expect(result?.recommendation).toBe("approve");
  });

  it("uses the model name constant for the API call", async () => {
    mockCreate.mockResolvedValue({
      content: [{ type: "text", text: JSON.stringify({
        recommendation: "approve",
        summary: "Fine.",
        concerns: [],
        confidence: 0.8,
      }) }],
    });
    const reviewer = new SkillAiReviewer("sk-ant-fake");
    await reviewer.review("x", "X", emptyScan);
    expect(mockCreate).toHaveBeenCalledOnce();
    const callArgs = mockCreate.mock.calls[0][0] as { model: string };
    expect(callArgs.model).toBe("claude-haiku-4-5-20251001");
  });
});
