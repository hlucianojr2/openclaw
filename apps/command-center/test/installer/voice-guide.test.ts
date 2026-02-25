/**
 * Tests for VoiceGuide and NARRATION scripts.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { VoiceGuide, NARRATION } from "../../src/main/installer/voice-guide.js";

// node-edge-tts is an optional dep; mock it so tests run without a network
vi.mock("node-edge-tts", () => ({
  EdgeTTS: class {
    async ttsPromise(_text: string, _path: string) {
      // no-op — test only exercises the class, not actual TTS
    }
  },
}));

// Mock child_process.exec and execAsync so no OS commands fire in tests
vi.mock("node:child_process", () => ({
  exec: vi.fn((_cmd: string, cb?: (err: null, stdout: string, stderr: string) => void) => {
    if (cb) { cb(null, "", ""); }
    const child = {
      pid: 9999,
      on: vi.fn((event: string, handler: (code: number) => void) => {
        // Immediately resolve the "close" listener so playAudioFile() doesn't hang
        if (event === "close") { handler(0); }
      }),
    };
    return child;
  }),
  promisify: vi.fn(() => vi.fn().mockResolvedValue({ stdout: "", stderr: "" })),
}));

// Mock fs/promises rm so no actual file operations happen
vi.mock("node:fs/promises", () => ({
  rm: vi.fn().mockResolvedValue(undefined),
}));

describe("VoiceGuide", () => {
  let guide: VoiceGuide;

  beforeEach(() => {
    guide = new VoiceGuide();
    vi.clearAllMocks();
  });

  it("is enabled by default", () => {
    expect(guide.isEnabled()).toBe(true);
  });

  it("setEnabled(false) disables narration", () => {
    guide.setEnabled(false);
    expect(guide.isEnabled()).toBe(false);
  });

  it("setEnabled(true) re-enables narration", () => {
    guide.setEnabled(false);
    guide.setEnabled(true);
    expect(guide.isEnabled()).toBe(true);
  });

  it("speak() resolves when disabled (no-op)", async () => {
    guide.setEnabled(false);
    await expect(guide.speak("hello")).resolves.toBeUndefined();
  });

  it("speak() returns a Promise that resolves after processing (queueDrain)", async () => {
    // Spy on processQueue so each iteration resolves immediately without
    // triggering the real audio path (exec "close" event never fires in tests).
    // The mock sets the speaking flag to simulate real behaviour so the second
    // speak() call coalesces onto the existing drain promise.
    const guideMut = guide as unknown as { speaking: boolean; processQueue: () => Promise<void> };
    vi.spyOn(guideMut, "processQueue").mockImplementation(async function pollDrain() {
      guideMut.speaking = true;
      await Promise.resolve();
      guideMut.speaking = false;
    });

    const p1 = guide.speak("first message");
    const p2 = guide.speak("second message");
    await expect(Promise.all([p1, p2])).resolves.toBeDefined();
  });

  it("stop() clears queue without throwing", () => {
    expect(() => guide.stop()).not.toThrow();
  });
});

describe("NARRATION", () => {
  it("has entries for all expected wizard steps", () => {
    const expectedKeys = [
      "welcome",
      "systemCheckPass",
      "systemCheckWarn",
      "systemCheckFail",
      "dockerMissing",
      "dockerFound",
      "llmSelect",
      "skillSelect",
      "channelSetup",
      "githubSetup",
      "review",
      "installing",
      "installingSkills",
      "configuringChannels",
      "complete",
    ];
    for (const key of expectedKeys) {
      expect(NARRATION[key], `Missing narration key: ${key}`).toBeTruthy();
    }
  });

  it("all narration strings are non-empty", () => {
    for (const [key, text] of Object.entries(NARRATION)) {
      expect(text.trim().length, `Empty narration for ${key}`).toBeGreaterThan(0);
    }
  });

  it("narration strings do not contain shell-unsafe characters", () => {
    // Sanity check — narration is passed to say/espeak; should not contain backticks or $()
    for (const [key, text] of Object.entries(NARRATION)) {
      expect(text, `${key} contains shell injection risk`).not.toMatch(/`|\$\(/);
    }
  });
});
