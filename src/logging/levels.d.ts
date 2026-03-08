export declare const ALLOWED_LOG_LEVELS: readonly ["silent", "fatal", "error", "warn", "info", "debug", "trace"];
export type LogLevel = (typeof ALLOWED_LOG_LEVELS)[number];
export declare function normalizeLogLevel(level?: string, fallback?: LogLevel): "debug" | "error" | "fatal" | "info" | "silent" | "trace" | "warn";
export declare function levelToMinLevel(level: LogLevel): number;
//# sourceMappingURL=levels.d.ts.map