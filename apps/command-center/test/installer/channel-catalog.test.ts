/**
 * Tests for the installer channel catalog and validation logic.
 */

import { describe, it, expect } from "vitest";
import {
  CHANNEL_CATALOG,
  getChannelsByCategory,
  getRecommendedChannels,
  findChannelById,
  validateChannelConfig,
} from "../../src/main/installer/channel-catalog.js";

describe("CHANNEL_CATALOG", () => {
  it("all channel IDs are unique", () => {
    const ids = CHANNEL_CATALOG.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("all entries have non-empty id, name, description, category", () => {
    for (const ch of CHANNEL_CATALOG) {
      expect(ch.id).toBeTruthy();
      expect(ch.name).toBeTruthy();
      expect(ch.description).toBeTruthy();
      expect(ch.category).toBeTruthy();
    }
  });

  it("all categories are valid", () => {
    const validCategories = new Set(["messaging", "team-chat", "email", "voice", "social", "dev"]);
    for (const ch of CHANNEL_CATALOG) {
      expect(validCategories.has(ch.category), `${ch.id}: invalid category ${ch.category}`).toBe(true);
    }
  });

  it("requiredFields have non-empty keys, labels, types", () => {
    for (const ch of CHANNEL_CATALOG) {
      for (const field of ch.requiredFields) {
        expect(field.key).toBeTruthy();
        expect(field.label).toBeTruthy();
        const validTypes = new Set(["text", "password", "number"]);
        expect(validTypes.has(field.type), `${ch.id}.${field.key}: invalid type`).toBe(true);
      }
    }
  });

  it("channls with requiresAppSetup have a setupGuideUrl", () => {
    for (const ch of CHANNEL_CATALOG) {
      if (ch.requiresAppSetup && ch.requiredFields.length > 0) {
        expect(ch.setupGuideUrl, `${ch.id} needs setupGuideUrl`).toBeTruthy();
      }
    }
  });
});

describe("getChannelsByCategory", () => {
  it("returns messaging channels", () => {
    const channels = getChannelsByCategory("messaging");
    expect(channels.length).toBeGreaterThan(0);
    for (const c of channels) { expect(c.category).toBe("messaging"); }
  });

  it("returns team-chat channels", () => {
    const channels = getChannelsByCategory("team-chat");
    expect(channels.length).toBeGreaterThan(0);
  });

  it("returns empty for unknown category", () => {
    // @ts-expect-error intentional invalid category for test
    expect(getChannelsByCategory("unknown-cat")).toHaveLength(0);
  });
});

describe("getRecommendedChannels", () => {
  it("returns at least one recommended channel", () => {
    expect(getRecommendedChannels().length).toBeGreaterThan(0);
  });

  it("all returned channels have recommended=true", () => {
    for (const c of getRecommendedChannels()) {
      expect(c.recommended).toBe(true);
    }
  });
});

describe("findChannelById", () => {
  it("finds telegram", () => {
    const ch = findChannelById("telegram");
    expect(ch).toBeDefined();
    expect(ch?.category).toBe("messaging");
    expect(ch?.recommended).toBe(true);
  });

  it("returns undefined for unknown id", () => {
    expect(findChannelById("this-does-not-exist")).toBeUndefined();
  });

  it("finds msteams", () => {
    const ch = findChannelById("msteams");
    expect(ch?.category).toBe("team-chat");
    expect(ch?.requiredFields.length).toBeGreaterThan(0);
  });
});

describe("validateChannelConfig", () => {
  it("returns valid for channel with no required fields (whatsapp)", () => {
    const result = validateChannelConfig("whatsapp", {});
    expect(result.valid).toBe(true);
  });

  it("returns invalid for unknown channel", () => {
    const result = validateChannelConfig("unknown-channel", {});
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/Unknown channel/);
  });

  it("returns invalid when required field is missing (telegram without botToken)", () => {
    const result = validateChannelConfig("telegram", {});
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/Bot Token/);
  });

  it("returns invalid when required field is empty string", () => {
    const result = validateChannelConfig("telegram", { botToken: "  " });
    expect(result.valid).toBe(false);
  });

  it("returns valid when all required fields are present (telegram)", () => {
    const result = validateChannelConfig("telegram", { botToken: "123:abc" });
    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it("returns valid for slack when all required fields provided", () => {
    const result = validateChannelConfig("slack", {
      botToken: "xoxb-test",
      appToken: "xapp-test",
    });
    expect(result.valid).toBe(true);
  });

  it("returns invalid for slack when appToken is missing", () => {
    const result = validateChannelConfig("slack", { botToken: "xoxb-test" });
    expect(result.valid).toBe(false);
  });

  it("returns valid for matrix when all required fields provided", () => {
    const result = validateChannelConfig("matrix", {
      homeserverUrl: "https://matrix.org",
      accessToken: "token123",
      userId: "@bot:matrix.org",
    });
    expect(result.valid).toBe(true);
  });

  it("irc — optional password does not block validation when absent", () => {
    const result = validateChannelConfig("irc", {
      server: "irc.libera.chat",
      nick: "occc-bot",
    });
    expect(result.valid).toBe(true);
  });
});
