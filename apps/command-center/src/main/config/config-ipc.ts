/**
 * Config IPC Handlers — exposes config read/write/validate/schema/reload/diff over IPC.
 *
 * All write operations require an ELEVATED session (re-auth).
 * Read operations require any valid session with config:read permission.
 *
 * Phase 4 additions: schema introspection, config reload, diff computation.
 */

import { ipcMain } from "electron";
import { ConfigStore } from "./config-store.js";
import { introspectSchema, deepDiff } from "./schema-introspector.js";
import type { SessionManager } from "../auth/session-manager.js";
import type { AuthSession, SchemaSectionMeta } from "../../shared/ipc-types.js";
import { hasPermission } from "../auth/rbac.js";
import { IPC_CHANNELS } from "../../shared/ipc-types.js";
import type { ConfigDiffEntry, ConfigValidationResult } from "../../shared/ipc-types.js";

// ─── Schema Import Cache ──────────────────────────────────────────────────

/**
 * Lazily loads the OpenClaw Zod schema + sensitive registry from the monorepo.
 * Cached after first successful import. Returns null if unavailable.
 */
let schemaCache: { OpenClawSchema: unknown; sensitive: unknown; zModule: unknown } | null | undefined;

async function loadSchema(): Promise<typeof schemaCache> {
  if (schemaCache !== undefined) { return schemaCache; }
  try {
    const schemaPath = new URL("../../../../../../src/config/zod-schema.js", import.meta.url);
    const sensitiveModPath = new URL(
      "../../../../../../src/config/zod-schema.sensitive.js",
      import.meta.url,
    );
    const zodPath = new URL("../../../../../../node_modules/zod/lib/index.mjs", import.meta.url);

    const [schemaModule, sensitiveModule, zModule] = await Promise.all([
      import(schemaPath.pathname),
      import(sensitiveModPath.pathname),
      import(zodPath.pathname),
    ]);

    schemaCache = {
      OpenClawSchema: schemaModule.OpenClawSchema,
      sensitive: sensitiveModule.sensitive,
      zModule,
    };
    return schemaCache;
  } catch {
    schemaCache = null;
    return null;
  }
}

// ─── Session Guards ─────────────────────────────────────────────────────────

function requireConfigRead(token: string, sessions: SessionManager) {
  const session = sessions.resolve(token);
  if (!session || !hasPermission(session.role, "config:read")) {
    throw new Error("Unauthorized");
  }
  return session;
}

function requireConfigWrite(token: string, sessions: SessionManager) {
  const session = sessions.resolve(token);
  if (!session || !hasPermission(session.role, "config:write")) {
    throw new Error("Unauthorized");
  }
  if (!session.elevated) {
    throw new Error("Elevation required to write configuration");
  }
  return session;
}

// ─── Handler Registration ───────────────────────────────────────────────────

export function registerConfigIpcHandlers(sessions: SessionManager): void {
  const store = new ConfigStore();

  // ─── Read (typed channel) ──────────────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.CONFIG_READ, async (_event, token: string) => {
    requireConfigRead(token, sessions);
    const result = await store.read();
    return { config: result.config, checksum: result.checksum, configPath: result.configPath };
  });

  // ─── Legacy Read (kept for backward compat with dev invoke()) ──────

  ipcMain.handle("occc:config:path", async (_event, token: string) => {
    const session = sessions.resolve(token);
    if (!session) { throw new Error("Unauthorized"); }
    return store.getConfigPath();
  });

  // ─── Config Path (typed channel) ───────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.CONFIG_PATH, async (_event, token: string) => {
    const session = sessions.resolve(token);
    if (!session) { throw new Error("Unauthorized"); }
    return store.getConfigPath();
  });

  // ─── Write (requires elevation, typed channel) ─────────────────────

  ipcMain.handle(
    IPC_CHANNELS.CONFIG_WRITE,
    async (_event, token: string, config: Record<string, unknown>, expectedChecksum?: string) => {
      requireConfigWrite(sessions, token);
      return store.write(config, expectedChecksum);
    },
  );

  // ─── Patch (requires elevation) ────────────────────────────────────

  ipcMain.handle(
    IPC_CHANNELS.CONFIG_PATCH,
    async (_event, token: string, patch: Record<string, unknown>, expectedChecksum?: string) => {
      requireConfigWrite(token, sessions);
      return store.patch(patch, expectedChecksum);
    },
  );

  // ─── Validate (typed channel) ──────────────────────────────────────

  ipcMain.handle(
    IPC_CHANNELS.CONFIG_VALIDATE,
    async (_event, token: string, config: Record<string, unknown>): Promise<ConfigValidationResult> => {
      requireConfigRead(token, sessions);
      const schema = await loadSchema();
      if (!schema) {
        return { valid: true, errors: [], note: "Schema validation unavailable in this environment" };
      }
      // Guard: verify the loaded module actually exports a Zod schema with safeParse
      // before calling it — a missing/mismatched schema export would otherwise throw.
      const validator = schema.OpenClawSchema;
      if (typeof validator !== "object" || validator === null || typeof (validator as Record<string, unknown>)["safeParse"] !== "function") {
        return { valid: true, errors: [], note: "Schema validation unavailable in this environment" };
      }
      type SafeParseResult = { success: boolean; error?: { issues: { path: (string | number)[]; message: string }[] } };
      const result = (validator as { safeParse(data: unknown): SafeParseResult }).safeParse(config);
      if (result.success) {
        return { valid: true, errors: [] };
      }
      const errors = (result.error?.issues ?? []).map((issue) => ({
        path: issue.path.join("."),
        message: issue.message,
      }));
      return { valid: false, errors };
    },
  );

  // ─── Schema Introspection (Phase 4) ────────────────────────────────

  ipcMain.handle(IPC_CHANNELS.CONFIG_SCHEMA, async (_event, token: string) => {
    requireConfigRead(token, sessions);
    const schema = await loadSchema();
    if (!schema) {
      return [];
    }
    // Cast to the internal ZodSchema shape expected by the introspector
    const sections = introspectSchema(
      schema.OpenClawSchema as Parameters<typeof introspectSchema>[0],
      schema.sensitive as Parameters<typeof introspectSchema>[1],
      schema.zModule as Parameters<typeof introspectSchema>[2],
    );
    return sections;
  });

  // ─── Diff (Phase 4) ────────────────────────────────────────────────

  ipcMain.handle(
    IPC_CHANNELS.CONFIG_DIFF,
    async (_event, token: string, pending: Record<string, unknown>): Promise<ConfigDiffEntry[]> => {
      requireConfigRead(token, sessions);
      if (typeof pending !== "object" || pending === null) {
        throw new Error("Invalid pending config: expected object");
      }
      const { config: saved } = await store.read();
      return deepDiff(saved, pending);
    },
  );

  // ─── Reload (Phase 4 — signal container to reload config) ─────────

  ipcMain.handle(
    IPC_CHANNELS.CONFIG_RELOAD,
    async (_event, token: string): Promise<{ ok: boolean; error?: string }> => {
      requireConfigWrite(token, sessions);
      // In OCCC, the config file is bind-mounted into the Docker container.
      // The gateway watches for changes via its reload mechanism; sending
      // SIGHUP to the container signals a graceful config reload.
      try {
        const { DockerEngineClient } = await import("../docker/engine-client.js");
        const { ContainerManager } = await import("../docker/container-manager.js");
        const client = new DockerEngineClient();
        const cm = new ContainerManager(client);
        const status = await cm.getEnvironmentStatus();
        if (status.gateway.state !== "running") {
          return { ok: false, error: "Gateway container is not running" };
        }
        // Send SIGHUP via the Docker API to trigger graceful reload.
        const container = client.getContainer(status.gateway.id);
        await container.kill({ signal: "SIGHUP" });
        return { ok: true };
      } catch (err: unknown) {
        return { ok: false, error: err instanceof Error ? err.message : String(err) };
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
