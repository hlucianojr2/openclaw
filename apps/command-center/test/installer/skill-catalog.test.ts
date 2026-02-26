/**
 * Tests for the installer skill catalog.
 */

import { describe, it, expect } from "vitest";
import {
  SKILL_CATALOG,
  getSkillsByApprovalLevel,
  getRecommendedSkills,
  findSkillById,
} from "../../src/main/installer/skill-catalog.js";

describe("SKILL_CATALOG", () => {
  it("contains only valid approval levels", () => {
    const validLevels = new Set(["auto-approved", "user-ack", "admin-review", "blocked"]);
    for (const skill of SKILL_CATALOG) {
      expect(validLevels.has(skill.approvalLevel), `${skill.id}: invalid approvalLevel`).toBe(true);
    }
  });

  it("contains only valid risk levels", () => {
    const validRisks = new Set(["low", "medium", "high", "blocked"]);
    for (const skill of SKILL_CATALOG) {
      expect(validRisks.has(skill.riskLevel), `${skill.id}: invalid riskLevel`).toBe(true);
    }
  });

  it("all skill IDs are unique", () => {
    const ids = SKILL_CATALOG.map((s) => s.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  it("has no entries with approvalLevel=blocked (blocked skills must not be shown in the catalog)", () => {
    const blocked = SKILL_CATALOG.filter((s) => s.approvalLevel === "blocked");
    expect(blocked).toHaveLength(0);
  });

  it("skills requiring an API key have an apiKeyLabel", () => {
    for (const skill of SKILL_CATALOG) {
      if (skill.requiresApiKey) {
        expect(skill.apiKeyLabel, `${skill.id} needs apiKeyLabel`).toBeTruthy();
      }
    }
  });

  it("all entries have non-empty id, name, description, category", () => {
    for (const skill of SKILL_CATALOG) {
      expect(skill.id).toBeTruthy();
      expect(skill.name).toBeTruthy();
      expect(skill.description).toBeTruthy();
      expect(skill.category).toBeTruthy();
    }
  });
});

describe("getSkillsByApprovalLevel", () => {
  it("returns only auto-approved skills", () => {
    const skills = getSkillsByApprovalLevel("auto-approved");
    expect(skills.length).toBeGreaterThan(0);
    for (const s of skills) {
      expect(s.approvalLevel).toBe("auto-approved");
    }
  });

  it("returns only user-ack skills", () => {
    const skills = getSkillsByApprovalLevel("user-ack");
    expect(skills.length).toBeGreaterThan(0);
    for (const s of skills) {
      expect(s.approvalLevel).toBe("user-ack");
    }
  });

  it("returns only admin-review skills", () => {
    const skills = getSkillsByApprovalLevel("admin-review");
    expect(skills.length).toBeGreaterThan(0);
    for (const s of skills) {
      expect(s.approvalLevel).toBe("admin-review");
    }
  });

  it("returns empty array for blocked level (none exist in catalog)", () => {
    const skills = getSkillsByApprovalLevel("blocked");
    expect(skills).toHaveLength(0);
  });
});

describe("getRecommendedSkills", () => {
  it("returns at least one recommended skill", () => {
    const skills = getRecommendedSkills();
    expect(skills.length).toBeGreaterThan(0);
  });

  it("all returned skills have recommended=true", () => {
    const skills = getRecommendedSkills();
    for (const s of skills) {
      expect(s.recommended).toBe(true);
    }
  });

  it("recommended skills are all auto-approved (low risk defaults)", () => {
    const skills = getRecommendedSkills();
    for (const s of skills) {
      expect(s.approvalLevel).toBe("auto-approved");
    }
  });
});

describe("findSkillById", () => {
  it("finds an existing skill by id", () => {
    const skill = findSkillById("healthcheck");
    expect(skill).toBeDefined();
    expect(skill?.id).toBe("healthcheck");
  });

  it("returns undefined for unknown id", () => {
    expect(findSkillById("does-not-exist")).toBeUndefined();
  });

  it("finds github skill", () => {
    const skill = findSkillById("github");
    expect(skill?.approvalLevel).toBe("user-ack");
    expect(skill?.requiresApiKey).toBe(true);
  });

  it("finds coding-agent as admin-review", () => {
    const skill = findSkillById("coding-agent");
    expect(skill?.approvalLevel).toBe("admin-review");
    expect(skill?.riskLevel).toBe("high");
  });
});
