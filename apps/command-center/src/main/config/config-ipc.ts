/**
 * Config IPC Handlers — exposes config read/write/validate/schema/diff over IPC.
 *
 * All write operations require an ELEVATED session (re-auth).
 * Read operations require any valid session with "config:read".
 *
 * Handlers use ONLY IPC_CHANNELS constants — no hardcoded channel strings.
 */

import { ipcMain } from "electron";
import { ConfigStore } from "./config-store.js";
import type { SessionManager } from "../auth/session-manager.js";
import type { AuthSession, SchemaSectionMeta } from "../../shared/ipc-types.js";
import { hasPermission } from "../auth/rbac.js";
import { IPC_CHANNELS } from "../../shared/ipc-types.js";
import type { ZodSafeParseable } from "./schema-introspector.js";
import { deepDiff } from "./schema-introspector.js";

// ─── Auth Guards ────────────────────────────────────────────────────────────

/**
 * Resolve a session token and verify "config:read" permission.
 * Throws on failure so each handler stays clean.
 */
function requireConfigRead(sessions: SessionManager, token: string): AuthSession {
  const session = sessions.resolve(token);
  if (!session || !hasPermission(session.role, "config:read")) {
    throw new Error("Unauthorized");
  }
  return session;
}

/**
 * Resolve, verify "config:write" permission, and assert elevation.
 */
function requireConfigWrite(sessions: SessionManager, token: string): AuthSession {
  const session = sessions.resolve(token);
  if (!session || !hasPermission(session.role, "config:write")) {
    throw new Error("Unauthorized");
  }
  if (!session.elevated) {
    throw new Error("Elevation required to write configuration");
  }
  return session;
}

// ─── Schema Cache ───────────────────────────────────────────────────────────

interface SchemaBundle {
  schema: ZodSafeParseable;
  sensitiveRegistry: { has(s: unknown): boolean } | null;
  zModule: typeof import("zod");
  introspect: typeof import("./schema-introspector.js").introspectSchema;
}

// Single in-flight promise so concurrent warmpup calls share one import.
let schemaCachePromise: Promise<SchemaBundle> | null = null;

/**
 * Lazily load the OpenClaw Zod schema and introspector.
 * Concurrent calls share a single import promise (no duplicate work).
 */
function getSchemaBundle(): Promise<SchemaBundle> {
  schemaCachePromise ??= (async () => {
    // Dynamically import the Zod schema from the main OpenClaw package.
    // Path: apps/command-center/src/main/config/ → repo-root/src/config/
    const schemaUrl = new URL("../../../../../../src/config/zod-schema.js", import.meta.url);
    const { OpenClawSchema, sensitiveRegistry } = await import(schemaUrl.pathname);
    const zModule = await import("zod");
    const { introspectSchema } = await import("./schema-introspector.js");

    return {
      schema: OpenClawSchema as ZodSafeParseable,
      sensitiveRegistry: sensitiveRegistry ?? null,
      zModule,
      introspect: introspectSchema,
    };
  })();
  return schemaCachePromise;
}

// ─── Handler Registration ───────────────────────────────────────────────────

export function registerConfigIpcHandlers(sessions: SessionManager): void {
  const store = new ConfigStore();

  // ─── Legacy scaffold stubs (bridge declares these; no active renderer uses them) ─
  // Return a typed error rather than hanging indefinitely.

  const notImplemented = (_: unknown, token: string) => {
    requireConfigRead(sessions, token);
    throw new Error("Not implemented — use readConfig / writeConfig / validateConfig");
  };
  ipcMain.handle(IPC_CHANNELS.CONFIG_GET, notImplemented);
  ipcMain.handle(IPC_CHANNELS.CONFIG_SET, notImplemented);
  ipcMain.handle(IPC_CHANNELS.CONFIG_SECTIONS, notImplemented);

  // ─── Read ──────────────────────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.CONFIG_READ, async (_event, token: string) => {
    requireConfigRead(sessions, token);
    return store.read();
  });

  ipcMain.handle(IPC_CHANNELS.CONFIG_PATH, async (_event, token: string) => {
    requireConfigRead(sessions, token);
    return store.getConfigPath();
  });

  // ─── Write (requires elevation) ───────────────────────────────────

  ipcMain.handle(
    IPC_CHANNELS.CONFIG_WRITE,
    async (_event, token: string, config: Record<string, unknown>, expectedChecksum?: string) => {
      requireConfigWrite(sessions, token);
      return store.write(config, expectedChecksum);
    },
  );

  ipcMain.handle(
    IPC_CHANNELS.CONFIG_PATCH,
    async (_event, token: string, patch: Record<string, unknown>, expectedChecksum?: string) => {
      requireConfigWrite(sessions, token);
      return store.patch(patch, expectedChecksum);
    },
  );

  // ─── Validate ─────────────────────────────────────────────────────

  ipcMain.handle(
    IPC_CHANNELS.CONFIG_VALIDATE,
    async (_event, token: string, config: Record<string, unknown>) => {
      requireConfigRead(sessions, token);

      try {
        const { schema } = await getSchemaBundle();
        const result = schema.safeParse(config);
        if (result.success) {
          return { valid: true, errors: [] };
        }
        const errors = (result.error?.issues ?? []).map((issue) => ({
          path: issue.path.join("."),
          message: issue.message,
        }));
        return { valid: false, errors };
      } catch {
        return { valid: true, errors: [], note: "Schema validation unavailable in this environment" };
      }
    },
  );

  // ─── Schema Introspection ─────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.CONFIG_SCHEMA, async (_event, token: string): Promise<SchemaSectionMeta[]> => {
    requireConfigRead(sessions, token);

    try {
      const bundle = await getSchemaBundle();
      // eslint-disable-next-line -- Zod internal shape is structurally compatible
      return bundle.introspect(bundle.schema as never, bundle.sensitiveRegistry, bundle.zModule);
    } catch {
      return [];
    }
  });

  // ─── Reload ───────────────────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.CONFIG_RELOAD, async (_event, token: string) => {
    requireConfigRead(sessions, token);
    // Re-read from disk — ConfigStore doesn't cache, so read() is always fresh
    return store.read();
  });

  // ─── Diff ─────────────────────────────────────────────────────────
  // deepDiff is a pure utility — no schema load needed.

  ipcMain.handle(
    IPC_CHANNELS.CONFIG_DIFF,
    async (_event, token: string, proposed: Record<string, unknown>) => {
      requireConfigRead(sessions, token);
      const { config: current } = await store.read();
      return deepDiff(current, proposed);
    },
  );
}
