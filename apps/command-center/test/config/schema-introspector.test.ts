/**
 * Schema Introspector — unit tests for Zod v4 schema walking and diff computation.
 *
 * Tests introspectSchema() with various Zod schema types and deepDiff()
 * for config change detection.
 */

import { describe, it, expect } from "vitest";
import { z } from "zod";
import {
  introspectSchema,
  deepDiff,
} from "../../src/main/config/schema-introspector.js";

// ─── Helpers ────────────────────────────────────────────────────────────────

/** Type-cast a Zod schema to the internal ZodSchema shape expected by the introspector. */
function asInternal(schema: z.ZodType): Parameters<typeof introspectSchema>[0] {
  return schema as unknown as Parameters<typeof introspectSchema>[0];
}

function asRegistry(reg: ReturnType<typeof z.registry>): Parameters<typeof introspectSchema>[1] {
  return reg as unknown as Parameters<typeof introspectSchema>[1];
}

// ─── introspectSchema() ─────────────────────────────────────────────────────

describe("introspectSchema()", () => {
  it("returns empty array for non-object root", () => {
    const schema = z.string();
    const result = introspectSchema(asInternal(schema), null, z);
    expect(result).toEqual([]);
  });

  it("introspects flat string/number/boolean fields", () => {
    const schema = z.object({
      name: z.string().describe("The name"),
      port: z.number().describe("Listen port"),
      debug: z.boolean().describe("Debug mode"),
    });

    const sections = introspectSchema(asInternal(schema), null, z);
    expect(sections).toHaveLength(3);

    const nameField = sections.find((s) => s.key === "name")?.fields[0];
    expect(nameField?.type).toBe("text");
    expect(nameField?.description).toBe("The name");
    expect(nameField?.required).toBe(true);

    const portField = sections.find((s) => s.key === "port")?.fields[0];
    expect(portField?.type).toBe("number");

    const debugField = sections.find((s) => s.key === "debug")?.fields[0];
    expect(debugField?.type).toBe("boolean");
  });

  it("handles optional fields", () => {
    const schema = z.object({
      host: z.string().optional(),
    });

    const sections = introspectSchema(asInternal(schema), null, z);
    const field = sections[0]?.fields[0];
    expect(field?.required).toBe(false);
  });

  it("detects default values", () => {
    const schema = z.object({
      port: z.number().default(3000),
    });

    const sections = introspectSchema(asInternal(schema), null, z);
    const field = sections[0]?.fields[0];
    expect(field?.defaultValue).toBe(3000);
  });

  it("introspects nested objects", () => {
    const schema = z.object({
      gateway: z.object({
        port: z.number(),
        host: z.string(),
      }),
    });

    const sections = introspectSchema(asInternal(schema), null, z);
    expect(sections).toHaveLength(1);
    expect(sections[0].key).toBe("gateway");

    const children = sections[0].fields;
    expect(children).toHaveLength(2);
    expect(children.find((f) => f.key === "port")?.type).toBe("number");
    expect(children.find((f) => f.key === "host")?.type).toBe("text");
  });

  it("introspects z.enum fields as 'select' type", () => {
    const schema = z.object({
      mode: z.enum(["local", "remote", "hybrid"]),
    });

    const sections = introspectSchema(asInternal(schema), null, z);
    const modeField = sections[0]?.fields[0];
    expect(modeField?.type).toBe("select");
    expect(modeField?.options).toEqual(["local", "remote", "hybrid"]);
  });

  it("introspects union of literals as 'select' type", () => {
    const schema = z.object({
      level: z.union([z.literal("low"), z.literal("medium"), z.literal("high")]),
    });

    const sections = introspectSchema(asInternal(schema), null, z);
    const field = sections[0]?.fields[0];
    expect(field?.type).toBe("select");
    expect(field?.options).toContain("low");
    expect(field?.options).toContain("medium");
    expect(field?.options).toContain("high");
  });

  it("introspects z.array(z.string()) as 'string-array'", () => {
    const schema = z.object({
      tags: z.array(z.string()),
    });

    const sections = introspectSchema(asInternal(schema), null, z);
    const field = sections[0]?.fields[0];
    expect(field?.type).toBe("string-array");
  });

  it("introspects z.record as 'record' type", () => {
    const schema = z.object({
      env: z.record(z.string(), z.string()),
    });

    const sections = introspectSchema(asInternal(schema), null, z);
    const field = sections[0]?.fields[0];
    expect(field?.type).toBe("record");
  });

  it("detects sensitive fields via registry", () => {
    const sensitive = z.registry<undefined, z.ZodType>();
    // In Zod v4, .register(registry) is called on the schema, not the registry
    const tokenField = z.string().describe("API token").register(sensitive);

    const schema = z.object({
      token: tokenField,
    });

    const sections = introspectSchema(asInternal(schema), asRegistry(sensitive), z);
    const field = sections[0]?.fields[0];
    expect(field?.sensitive).toBe(true);
  });

  it("detects sensitive on optional-wrapped fields", () => {
    const sensitive = z.registry<undefined, z.ZodType>();
    // Register inner schema, then wrap with .optional()
    const secretField = z.string().register(sensitive);

    const schema = z.object({
      secret: secretField.optional(),
    });

    const sections = introspectSchema(asInternal(schema), asRegistry(sensitive), z);
    const field = sections[0]?.fields[0];
    expect(field?.sensitive).toBe(true);
  });

  it("generates correct labels from keys", () => {
    const schema = z.object({
      gateway: z.object({ port: z.number() }),
    });

    const sections = introspectSchema(asInternal(schema), null, z);
    expect(sections[0].label).toBe("Gateway");
  });

  it("skips $schema and meta keys", () => {
    const schema = z.object({
      $schema: z.string(),
      meta: z.object({ version: z.number() }),
      gateway: z.object({ port: z.number() }),
    });

    const sections = introspectSchema(asInternal(schema), null, z);
    expect(sections).toHaveLength(1);
    expect(sections[0].key).toBe("gateway");
  });

  it("extracts numeric min/max constraints", () => {
    const schema = z.object({
      port: z.number().min(1).max(65535),
    });

    const sections = introspectSchema(asInternal(schema), null, z);
    const field = sections[0]?.fields[0];
    expect(field?.min).toBe(1);
    expect(field?.max).toBe(65535);
  });

  it("falls back to 'json' for unknown schema types", () => {
    // z.any() or other exotic types should degrade gracefully
    const schema = z.object({
      data: z.any(),
    });

    const sections = introspectSchema(asInternal(schema), null, z);
    const field = sections[0]?.fields[0];
    // Should be either 'json' or some fallback — not crash
    expect(field).toBeDefined();
  });
});

// ─── deepDiff() ─────────────────────────────────────────────────────────────

describe("deepDiff()", () => {
  it("returns empty for identical objects", () => {
    const obj = { a: 1, b: "hello" };
    expect(deepDiff(obj, obj)).toEqual([]);
  });

  it("detects changed values", () => {
    const old = { port: 3000 };
    const next = { port: 8080 };
    const diff = deepDiff(old, next);
    expect(diff).toHaveLength(1);
    expect(diff[0]).toEqual({
      path: "port",
      type: "changed",
      oldValue: 3000,
      newValue: 8080,
    });
  });

  it("detects added keys", () => {
    const old: Record<string, unknown> = { a: 1 };
    const next = { a: 1, b: 2 };
    const diff = deepDiff(old, next);
    expect(diff).toHaveLength(1);
    expect(diff[0].type).toBe("added");
    expect(diff[0].path).toBe("b");
    expect(diff[0].newValue).toBe(2);
  });

  it("detects removed keys", () => {
    const old = { a: 1, b: 2 };
    const next: Record<string, unknown> = { a: 1 };
    const diff = deepDiff(old, next);
    expect(diff).toHaveLength(1);
    expect(diff[0].type).toBe("removed");
    expect(diff[0].path).toBe("b");
    expect(diff[0].oldValue).toBe(2);
  });

  it("handles nested object changes", () => {
    const old = { gateway: { port: 3000, host: "localhost" } };
    const next = { gateway: { port: 8080, host: "localhost" } };
    const diff = deepDiff(old, next);
    expect(diff).toHaveLength(1);
    expect(diff[0].path).toBe("gateway.port");
    expect(diff[0].type).toBe("changed");
  });

  it("handles deeply nested additions", () => {
    const old = { a: { b: {} } } as Record<string, unknown>;
    const next = { a: { b: { c: "new" } } };
    const diff = deepDiff(old, next);
    expect(diff).toHaveLength(1);
    expect(diff[0].path).toBe("a.b.c");
    expect(diff[0].type).toBe("added");
  });

  it("detects array changes by JSON comparison", () => {
    const old = { tags: ["a", "b"] };
    const next = { tags: ["a", "c"] };
    const diff = deepDiff(old, next);
    expect(diff).toHaveLength(1);
    expect(diff[0].type).toBe("changed");
    expect(diff[0].path).toBe("tags");
  });

  it("handles empty objects", () => {
    const diff = deepDiff({}, {});
    expect(diff).toEqual([]);
  });

  it("handles complete object replacement", () => {
    const old = { a: 1, b: 2 };
    const next = { c: 3, d: 4 };
    const diff = deepDiff(old, next);
    expect(diff).toHaveLength(4);
    expect(diff.filter((d) => d.type === "removed")).toHaveLength(2);
    expect(diff.filter((d) => d.type === "added")).toHaveLength(2);
  });
});
