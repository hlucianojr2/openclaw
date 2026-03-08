/**
 * Schema Introspector — walks a Zod v4 schema to extract field metadata
 * for auto-generating config forms in the renderer.
 *
 * Handles:
 *   - z.object → nested section with children
 *   - z.string / z.number / z.boolean → primitive fields
 *   - z.union of literals → select/enum dropdown
 *   - z.enum → select/enum dropdown
 *   - z.array(z.string()) → string-array field
 *   - z.record → record/map field
 *   - z.optional / z.default → unwraps inner type
 *   - .register(sensitive) → sensitive=true (password masking)
 *   - z.toJSONSchema → extracts min/max constraints
 *
 * The introspector is intentionally lenient: unknown schema shapes fall back
 * to a "json" field type so the form always renders something editable.
 */

import type { z } from "zod";

// ─── Output Types ───────────────────────────────────────────────────────────

export type SchemaFieldType =
  | "text"
  | "password"
  | "number"
  | "boolean"
  | "select"
  | "string-array"
  | "record"
  | "json";

export interface SchemaFieldMeta {
  /** Field key within its parent object. */
  key: string;
  /** Full dotted path from root (e.g. ["gateway", "auth", "mode"]). */
  path: string[];
  /** Renderer field type. */
  type: SchemaFieldType;
  /** Whether the field is required (not optional). */
  required: boolean;
  /** Whether the value contains secrets (tokens, passwords, API keys). */
  sensitive: boolean;
  /** Human-readable description from `.describe()`. */
  description?: string;
  /** Enum/select options (for union-of-literals or z.enum). */
  options?: string[];
  /** Numeric minimum constraint. */
  min?: number;
  /** Numeric maximum constraint. */
  max?: number;
  /** Default value from z.default(). */
  defaultValue?: unknown;
  /** Child fields for nested objects. */
  children?: SchemaFieldMeta[];
}

export interface SchemaSectionMeta {
  /** Top-level key in the config object (e.g. "gateway", "agents"). */
  key: string;
  /** Human-readable label derived from the key. */
  label: string;
  /** Flat + nested field metadata. */
  fields: SchemaFieldMeta[];
}

// ─── Internal Zod v4 Def Types ──────────────────────────────────────────────

// Minimal typings for Zod v4 internal `_zod.def` — just enough for walking.
interface ZodDef {
  type: string;
  shape?: Record<string, ZodSchema>;
  options?: ZodSchema[];
  values?: unknown[];
  entries?: Record<string, string>;
  element?: ZodSchema;
  innerType?: ZodSchema;
  keyType?: ZodSchema;
  valueType?: ZodSchema;
  defaultValue?: unknown;
  checks?: unknown[];
  catchall?: ZodSchema;
}

interface ZodInternals {
  def: ZodDef;
}

interface ZodSchema {
  _zod: ZodInternals;
  description?: string;
}

// ─── Sensitive Registry Detection ───────────────────────────────────────────

type SensitiveRegistry = { has(schema: ZodSchema): boolean } | null;

/** Check if a schema (or its unwrapped inner type) is registered as sensitive. */
function isSensitive(schema: ZodSchema, registry: SensitiveRegistry): boolean {
  if (!registry) { return false; }
  if (registry.has(schema)) { return true; }
  // When `.optional().register(sensitive)` — the optional wrapper is registered.
  // When `.register(sensitive).optional()` — the inner type is registered.
  const inner = schema._zod.def.innerType;
  if (inner && registry.has(inner)) { return true; }
  return false;
}

// ─── JSON Schema Constraint Extraction ──────────────────────────────────────

/**
 * Try to extract min/max from a number schema's check constructors.
 * Falls back gracefully if checks aren't inspectable.
 */
function extractNumericConstraints(
  schema: ZodSchema,
  zModule: typeof z,
): { min?: number; max?: number } {
  const result: { min?: number; max?: number } = {};
  try {
    // eslint-disable-next-line -- dynamic schema from introspection, not statically typed
    const jsonSchema = zModule.toJSONSchema(schema as never) as Record<string, unknown>;
    if (typeof jsonSchema.minimum === "number") { result.min = jsonSchema.minimum; }
    if (typeof jsonSchema.maximum === "number") { result.max = jsonSchema.maximum; }
    if (typeof jsonSchema.exclusiveMinimum === "number") {
      result.min = jsonSchema.exclusiveMinimum;
    }
    if (typeof jsonSchema.exclusiveMaximum === "number") {
      result.max = jsonSchema.exclusiveMaximum;
    }
  } catch {
    // toJSONSchema may fail for complex schemas — ignore
  }
  return result;
}

// ─── Core Walker ────────────────────────────────────────────────────────────

/**
 * Recursively walk a Zod schema and extract field metadata.
 *
 * @param key - Field key within parent object
 * @param schema - Zod schema to inspect
 * @param path - Accumulated path segments
 * @param registry - Sensitive field registry (or null)
 * @param zModule - The Zod module (for toJSONSchema)
 */
function walkField(
  key: string,
  schema: ZodSchema,
  path: string[],
  registry: SensitiveRegistry,
  zModule: typeof z,
): SchemaFieldMeta {
  const sensitive = isSensitive(schema, registry);
  const description = schema.description;
  const fieldPath = [...path, key];
  let required = true;
  let defaultValue: unknown;

  // Unwrap optional / default wrappers
  let current = schema;
  while (
    current._zod.def.type === "optional" ||
    current._zod.def.type === "default" ||
    current._zod.def.type === "exact_optional"
  ) {
    if (current._zod.def.type === "optional" || current._zod.def.type === "exact_optional") {
      required = false;
    }
    if (current._zod.def.type === "default") {
      required = false;
      defaultValue = current._zod.def.defaultValue;
    }
    if (current._zod.def.innerType) {
      current = current._zod.def.innerType;
    } else {
      break;
    }
  }

  const defType = current._zod.def.type;

  // ─── Primitives ─────────────────────────────────────────────────

  if (defType === "string") {
    return {
      key,
      path: fieldPath,
      type: sensitive ? "password" : "text",
      required,
      sensitive,
      description,
      defaultValue,
    };
  }

  if (defType === "number" || defType === "bigint") {
    const constraints = extractNumericConstraints(current, zModule);
    return {
      key,
      path: fieldPath,
      type: "number",
      required,
      sensitive: false,
      description,
      defaultValue,
      ...constraints,
    };
  }

  if (defType === "boolean") {
    return {
      key,
      path: fieldPath,
      type: "boolean",
      required,
      sensitive: false,
      description,
      defaultValue,
    };
  }

  // ─── Enum → select ─────────────────────────────────────────────

  if (defType === "enum" && current._zod.def.entries) {
    const options = Object.values(current._zod.def.entries);
    return {
      key,
      path: fieldPath,
      type: "select",
      required,
      sensitive: false,
      description,
      options,
      defaultValue,
    };
  }

  // ─── Literal → treat as a fixed-value text field ────────────────

  if (defType === "literal" && current._zod.def.values) {
    const values = current._zod.def.values as string[];
    if (values.length === 1 && typeof values[0] === "string") {
      return {
        key,
        path: fieldPath,
        type: "select",
        required,
        sensitive: false,
        description,
        options: values,
        defaultValue,
      };
    }
  }

  // ─── Union of literals → select dropdown ────────────────────────

  if (defType === "union" && current._zod.def.options) {
    const opts = current._zod.def.options;
    const allLiterals = opts.every(
      (o: ZodSchema) => o._zod.def.type === "literal" && o._zod.def.values,
    );
    if (allLiterals) {
      const options = opts.flatMap((o: ZodSchema) =>
        (o._zod.def.values as unknown[]).filter(
          (v): v is string => typeof v === "string",
        ),
      );
      if (options.length > 0) {
        return {
          key,
          path: fieldPath,
          type: "select",
          required,
          sensitive: false,
          description,
          options,
          defaultValue,
        };
      }
    }
    // Union of non-literals — fall through to json
  }

  // ─── Array of strings → string-array ────────────────────────────

  if (defType === "array" && current._zod.def.element) {
    const elemType = current._zod.def.element._zod.def.type;
    if (elemType === "string") {
      return {
        key,
        path: fieldPath,
        type: "string-array",
        required,
        sensitive: false,
        description,
        defaultValue,
      };
    }
    // Array of non-strings — json fallback
    return {
      key,
      path: fieldPath,
      type: "json",
      required,
      sensitive: false,
      description,
      defaultValue,
    };
  }

  // ─── Record → record field ──────────────────────────────────────

  if (defType === "record") {
    return {
      key,
      path: fieldPath,
      type: "record",
      required,
      sensitive,
      description,
      defaultValue,
    };
  }

  // ─── Object → recurse into children ────────────────────────────

  if (defType === "object" && current._zod.def.shape) {
    const shape = current._zod.def.shape;
    const children: SchemaFieldMeta[] = [];
    for (const [childKey, childSchema] of Object.entries(shape)) {
      children.push(walkField(childKey, childSchema, fieldPath, registry, zModule));
    }
    return {
      key,
      path: fieldPath,
      type: "json",
      required,
      sensitive: false,
      description,
      children,
      defaultValue,
    };
  }

  // ─── Fallback → json textarea ──────────────────────────────────

  return {
    key,
    path: fieldPath,
    type: "json",
    required,
    sensitive: false,
    description,
    defaultValue,
  };
}

// ─── Public API ─────────────────────────────────────────────────────────────

/** Human-readable label from a camelCase or kebab-case key. */
function keyToLabel(key: string): string {
  return key
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/[-_]/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

/**
 * Walk the top-level keys of an OpenClaw Zod schema and produce
 * section metadata for each one. Sections with no inspectable fields
 * are omitted.
 *
 * @param schema - The root z.object() schema (e.g. OpenClawSchema)
 * @param sensitiveRegistry - The sensitive field registry from zod-schema.sensitive.ts
 * @param zModule - The Zod module reference (for toJSONSchema)
 */
export function introspectSchema(
  schema: ZodSchema,
  sensitiveRegistry: SensitiveRegistry,
  zModule: typeof z,
): SchemaSectionMeta[] {
  if (schema._zod.def.type !== "object" || !schema._zod.def.shape) {
    return [];
  }

  const shape = schema._zod.def.shape;
  const sections: SchemaSectionMeta[] = [];

  for (const [key, childSchema] of Object.entries(shape)) {
    // Skip meta / $schema — not user-editable
    if (key === "$schema" || key === "meta") { continue; }

    const field = walkField(key, childSchema, [], sensitiveRegistry, zModule);
    // If the top-level field has children, flatten them into section fields.
    // Otherwise wrap it as a single-field section.
    const fields = field.children ?? [field];

    sections.push({
      key,
      label: keyToLabel(key),
      fields,
    });
  }

  return sections;
}

// ─── Deep Diff ──────────────────────────────────────────────────────────────

export interface DiffEntry {
  /** Dotted path (e.g. "gateway.port"). */
  path: string;
  type: "added" | "removed" | "changed";
  oldValue?: unknown;
  newValue?: unknown;
}

/**
 * Compute a deep diff between two config objects.
 * Returns an array of path-level changes. Arrays and non-object values
 * are compared by JSON serialization for simplicity.
 */
export function deepDiff(
  oldObj: Record<string, unknown>,
  newObj: Record<string, unknown>,
  prefix = "",
): DiffEntry[] {
  const entries: DiffEntry[] = [];
  const allKeys = new Set([...Object.keys(oldObj), ...Object.keys(newObj)]);

  for (const key of allKeys) {
    const path = prefix ? `${prefix}.${key}` : key;
    const oldVal = oldObj[key];
    const newVal = newObj[key];

    const oldExists = key in oldObj;
    const newExists = key in newObj;

    if (!oldExists && newExists) {
      entries.push({ path, type: "added", newValue: newVal });
      continue;
    }
    if (oldExists && !newExists) {
      entries.push({ path, type: "removed", oldValue: oldVal });
      continue;
    }

    // Both exist — compare
    if (isPlainObject(oldVal) && isPlainObject(newVal)) {
      entries.push(
        ...deepDiff(oldVal, newVal, path),
      );
    } else if (JSON.stringify(oldVal) !== JSON.stringify(newVal)) {
      entries.push({ path, type: "changed", oldValue: oldVal, newValue: newVal });
    }
  }

  return entries;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}
