/**
 * Unit tests for the schema introspector and deepDiff utility.
 */

import { describe, it, expect } from "vitest";
import { introspectSchema, deepDiff } from "../../src/main/config/schema-introspector.js";
import type { SchemaSectionMeta, SchemaFieldMeta } from "../../src/main/config/schema-introspector.js";

// ─── Minimal Zod v4 Stubs ──────────────────────────────────────────────────

// Instead of importing the real Zod (which may have side-effects or need
// complex setup), we build schema-shaped objects that match the introspection
// expectations. This keeps tests fast and isolated.

interface StubSchema {
  _zod: { def: Record<string, unknown> };
  description?: string;
}

function stub(defType: string, extra: Record<string, unknown> = {}, description?: string): StubSchema {
  return {
    _zod: { def: { type: defType, ...extra } },
    ...(description ? { description } : {}),
  };
}

/** Produces a stub z.object({ ...shape }) */
function stubObject(shape: Record<string, StubSchema>): StubSchema {
  return stub("object", { shape });
}

/** Produces a stub z.optional(inner) */
function stubOptional(inner: StubSchema): StubSchema {
  return stub("optional", { innerType: inner });
}

/** Produces a stub z.default(inner, value) */
function stubDefault(inner: StubSchema, defaultValue: unknown): StubSchema {
  return stub("default", { innerType: inner, defaultValue });
}

/** Produces a stub z.union of literals */
function stubUnionOfLiterals(values: string[]): StubSchema {
  return stub("union", {
    options: values.map((v) => stub("literal", { values: [v] })),
  });
}

/** Produces a stub z.enum */
function stubEnum(values: string[]): StubSchema {
  const entries: Record<string, string> = {};
  for (const v of values) { entries[v] = v; }
  return stub("enum", { entries });
}

/** Produces a stub z.array(z.string()) */
function stubStringArray(): StubSchema {
  return stub("array", { element: stub("string") });
}

/** Produces a stub z.record(z.string(), z.string()) */
function stubRecord(): StubSchema {
  return stub("record", {});
}

// Stub for z module (only toJSONSchema is called by extractNumericConstraints)
const stubZModule = {
  toJSONSchema: () => ({}),
} as unknown as typeof import("zod");

// ─── introspectSchema() ─────────────────────────────────────────────────────

describe("introspectSchema()", () => {
  it("returns empty for non-object schemas", () => {
    const result = introspectSchema(stub("string") as never, null, stubZModule);
    expect(result).toEqual([]);
  });

  it("returns sections for a top-level object with nested objects", () => {
    const schema = stubObject({
      gateway: stubObject({
        port: stub("number", {}, "The gateway port"),
        host: stub("string"),
      }),
    });

    const sections = introspectSchema(schema as never, null, stubZModule);
    expect(sections).toHaveLength(1);
    expect(sections[0].key).toBe("gateway");
    expect(sections[0].label).toBe("Gateway");
    expect(sections[0].fields).toHaveLength(2);

    const portField = sections[0].fields.find((f) => f.key === "port");
    expect(portField?.type).toBe("number");
    expect(portField?.description).toBe("The gateway port");
  });

  it("strips $schema and meta keys", () => {
    const schema = stubObject({
      $schema: stub("string"),
      meta: stubObject({}),
      gateway: stub("string"),
    });

    const sections = introspectSchema(schema as never, null, stubZModule);
    expect(sections).toHaveLength(1);
    expect(sections[0].key).toBe("gateway");
  });

  it("maps string fields to 'text' type", () => {
    const schema = stubObject({
      section: stubObject({ name: stub("string") }),
    });

    const sections = introspectSchema(schema as never, null, stubZModule);
    const field = sections[0].fields[0];
    expect(field.type).toBe("text");
    expect(field.sensitive).toBe(false);
  });

  it("maps boolean fields", () => {
    const schema = stubObject({
      section: stubObject({ enabled: stub("boolean") }),
    });

    const sections = introspectSchema(schema as never, null, stubZModule);
    expect(sections[0].fields[0].type).toBe("boolean");
  });

  it("maps number fields without constraints", () => {
    const schema = stubObject({
      section: stubObject({ count: stub("number") }),
    });

    const sections = introspectSchema(schema as never, null, stubZModule);
    const field = sections[0].fields[0];
    expect(field.type).toBe("number");
    expect(field.min).toBeUndefined();
    expect(field.max).toBeUndefined();
  });

  it("extracts numeric constraints from toJSONSchema", () => {
    const zWithConstraints = {
      toJSONSchema: () => ({ minimum: 1, maximum: 100 }),
    } as unknown as typeof import("zod");

    const schema = stubObject({
      section: stubObject({ count: stub("number") }),
    });

    const sections = introspectSchema(schema as never, null, zWithConstraints);
    const field = sections[0].fields[0];
    expect(field.min).toBe(1);
    expect(field.max).toBe(100);
  });

  it("maps union of literals to 'select' type", () => {
    const schema = stubObject({
      section: stubObject({ mode: stubUnionOfLiterals(["fast", "slow", "normal"]) }),
    });

    const sections = introspectSchema(schema as never, null, stubZModule);
    const field = sections[0].fields[0];
    expect(field.type).toBe("select");
    expect(field.options).toEqual(["fast", "slow", "normal"]);
  });

  it("maps z.enum to 'select' type", () => {
    const schema = stubObject({
      section: stubObject({ level: stubEnum(["info", "warn", "error"]) }),
    });

    const sections = introspectSchema(schema as never, null, stubZModule);
    const field = sections[0].fields[0];
    expect(field.type).toBe("select");
    expect(field.options).toEqual(["info", "warn", "error"]);
  });

  it("maps z.array(z.string()) to 'string-array' type", () => {
    const schema = stubObject({
      section: stubObject({ tags: stubStringArray() }),
    });

    const sections = introspectSchema(schema as never, null, stubZModule);
    expect(sections[0].fields[0].type).toBe("string-array");
  });

  it("maps z.record to 'record' type", () => {
    const schema = stubObject({
      section: stubObject({ env: stubRecord() }),
    });

    const sections = introspectSchema(schema as never, null, stubZModule);
    expect(sections[0].fields[0].type).toBe("record");
  });

  it("unwraps optional and marks required=false", () => {
    const schema = stubObject({
      section: stubObject({ opt: stubOptional(stub("string")) }),
    });

    const sections = introspectSchema(schema as never, null, stubZModule);
    const field = sections[0].fields[0];
    expect(field.required).toBe(false);
    expect(field.type).toBe("text");
  });

  it("unwraps default and records defaultValue", () => {
    const schema = stubObject({
      section: stubObject({ port: stubDefault(stub("number"), 8080) }),
    });

    const sections = introspectSchema(schema as never, null, stubZModule);
    const field = sections[0].fields[0];
    expect(field.required).toBe(false);
    expect(field.defaultValue).toBe(8080);
    expect(field.type).toBe("number");
  });

  it("marks fields as sensitive when registry matches", () => {
    const tokenSchema = stub("string");
    const schema = stubObject({
      section: stubObject({ token: tokenSchema }),
    });
    const registry = { has: (s: unknown) => s === tokenSchema };

    const sections = introspectSchema(schema as never, registry as never, stubZModule);
    expect(sections[0].fields[0].sensitive).toBe(true);
    expect(sections[0].fields[0].type).toBe("password");
  });

  it("marks fields as sensitive when inner (optional-wrapped) schema is in registry", () => {
    const inner = stub("string");
    const optionalSchema = stubOptional(inner);
    const schema = stubObject({
      section: stubObject({ secret: optionalSchema }),
    });
    const registry = { has: (s: unknown) => s === inner };

    const sections = introspectSchema(schema as never, registry as never, stubZModule);
    expect(sections[0].fields[0].sensitive).toBe(true);
  });

  it("falls back to 'json' type for unknown schema shapes", () => {
    const schema = stubObject({
      section: stubObject({ complex: stub("intersection") }),
    });

    const sections = introspectSchema(schema as never, null, stubZModule);
    expect(sections[0].fields[0].type).toBe("json");
  });

  it("builds correct field paths", () => {
    const schema = stubObject({
      gateway: stubObject({
        auth: stubObject({
          mode: stub("string"),
        }),
      }),
    });

    const sections = introspectSchema(schema as never, null, stubZModule);
    const authField = sections[0].fields[0];
    expect(authField.key).toBe("auth");
    // auth is a nested object — its children should have full paths
    expect(authField.children).toBeDefined();
    const modeField = authField.children![0];
    expect(modeField.path).toEqual(["gateway", "auth", "mode"]);
  });

  it("generates labels with proper casing", () => {
    const schema = stubObject({
      gatewayAuth: stubObject({ apiKey: stub("string") }),
    });

    const sections = introspectSchema(schema as never, null, stubZModule);
    expect(sections[0].label).toBe("Gateway Auth");
  });

  it("handles top-level primitive fields (non-object sections)", () => {
    const schema = stubObject({
      version: stub("string"),
    });

    const sections = introspectSchema(schema as never, null, stubZModule);
    expect(sections).toHaveLength(1);
    expect(sections[0].key).toBe("version");
    // A non-object top-level key yields a single-field section
    expect(sections[0].fields).toHaveLength(1);
    expect(sections[0].fields[0].type).toBe("text");
  });

  it("handles z.array of non-strings as json fallback", () => {
    const schema = stubObject({
      section: stubObject({
        items: stub("array", { element: stub("number") }),
      }),
    });

    const sections = introspectSchema(schema as never, null, stubZModule);
    expect(sections[0].fields[0].type).toBe("json");
  });

  it("returns correct SchemaSectionMeta shape", () => {
    const schema = stubObject({
      providers: stubObject({ apiKey: stub("string") }),
    });

    const sections: SchemaSectionMeta[] = introspectSchema(schema as never, null, stubZModule);
    expect(sections[0]).toMatchObject({
      key: "providers",
      label: "Providers",
      fields: expect.any(Array) as SchemaFieldMeta[],
    });
  });
});

// ─── deepDiff() ─────────────────────────────────────────────────────────────

describe("deepDiff()", () => {
  it("returns empty for identical objects", () => {
    const obj = { a: 1, b: "hello" };
    expect(deepDiff(obj, obj)).toEqual([]);
  });

  it("detects added keys", () => {
    const result = deepDiff({}, { newKey: "val" });
    expect(result).toEqual([
      { path: "newKey", type: "added", newValue: "val" },
    ]);
  });

  it("detects removed keys", () => {
    const result = deepDiff({ oldKey: 42 }, {});
    expect(result).toEqual([
      { path: "oldKey", type: "removed", oldValue: 42 },
    ]);
  });

  it("detects changed primitive values", () => {
    const result = deepDiff({ port: 8080 }, { port: 9090 });
    expect(result).toEqual([
      { path: "port", type: "changed", oldValue: 8080, newValue: 9090 },
    ]);
  });

  it("recurses into nested objects", () => {
    const old = { gateway: { port: 8080, host: "localhost" } };
    const cur = { gateway: { port: 9090, host: "localhost" } };
    const result = deepDiff(old, cur);
    expect(result).toEqual([
      { path: "gateway.port", type: "changed", oldValue: 8080, newValue: 9090 },
    ]);
  });

  it("detects nested additions and removals", () => {
    const old = { a: { b: 1 } };
    const cur = { a: { c: 2 } };
    const result = deepDiff(old, cur);
    expect(result).toHaveLength(2);
    expect(result).toContainEqual({ path: "a.b", type: "removed", oldValue: 1 });
    expect(result).toContainEqual({ path: "a.c", type: "added", newValue: 2 });
  });

  it("compares arrays by JSON serialization", () => {
    const old = { list: [1, 2, 3] };
    const cur = { list: [1, 2, 4] };
    const result = deepDiff(old, cur);
    expect(result).toEqual([
      { path: "list", type: "changed", oldValue: [1, 2, 3], newValue: [1, 2, 4] },
    ]);
  });

  it("treats identical arrays as no change", () => {
    const old = { list: [1, 2, 3] };
    const cur = { list: [1, 2, 3] };
    expect(deepDiff(old, cur)).toEqual([]);
  });

  it("handles multiple simultaneous changes", () => {
    const old = { a: 1, b: 2, c: 3 };
    const cur = { a: 10, b: 2, d: 4 };
    const result = deepDiff(old, cur);
    expect(result).toHaveLength(3);
    expect(result).toContainEqual({ path: "a", type: "changed", oldValue: 1, newValue: 10 });
    expect(result).toContainEqual({ path: "c", type: "removed", oldValue: 3 });
    expect(result).toContainEqual({ path: "d", type: "added", newValue: 4 });
  });

  it("returns empty for two empty objects", () => {
    expect(deepDiff({}, {})).toEqual([]);
  });

  it("respects maxDepth and stops recursing", () => {
    const old = { a: { b: { c: { d: 1 } } } };
    const cur = { a: { b: { c: { d: 2 } } } };

    // With maxDepth=2, should compare a.b.c as JSON rather than recursing into d
    const result = deepDiff(old, cur, "", 2);
    expect(result).toHaveLength(1);
    expect(result[0].path).toBe("a.b.c");
    expect(result[0].type).toBe("changed");
  });

  it("uses default maxDepth of 20", () => {
    // Build a deeply nested structure (15 levels deep)
    let old: Record<string, unknown> = { val: 1 };
    let cur: Record<string, unknown> = { val: 2 };
    for (let i = 0; i < 15; i++) {
      old = { nested: old };
      cur = { nested: cur };
    }
    // Should not stack overflow and should detect the change
    const result = deepDiff(old, cur);
    expect(result).toHaveLength(1);
    expect(result[0].type).toBe("changed");
  });

  it("at maxDepth=0, compares objects by JSON serialization", () => {
    const old = { a: { deep: 1 } };
    const cur = { a: { deep: 2 } };
    const result = deepDiff(old, cur, "", 0);
    expect(result).toHaveLength(1);
    expect(result[0].path).toBe("a");
    expect(result[0].type).toBe("changed");
  });

  it("handles null values correctly", () => {
    const old = { key: null as unknown };
    const cur = { key: "value" };
    const result = deepDiff(old, cur);
    expect(result).toEqual([
      { path: "key", type: "changed", oldValue: null, newValue: "value" },
    ]);
  });
});
