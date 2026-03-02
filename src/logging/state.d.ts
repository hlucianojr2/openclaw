export declare const loggingState: {
    cachedLogger: unknown;
    cachedSettings: unknown;
    cachedConsoleSettings: unknown;
    overrideSettings: unknown;
    consolePatched: boolean;
    forceConsoleToStderr: boolean;
    consoleTimestampPrefix: boolean;
    consoleSubsystemFilter: string[] | null;
    resolvingConsoleSettings: boolean;
    streamErrorHandlersInstalled: boolean;
    rawConsole: {
        log: {
            (...data: any[]): void;
            (...data: any[]): void;
        };
        info: {
            (...data: any[]): void;
            (...data: any[]): void;
        };
        warn: {
            (...data: any[]): void;
            (...data: any[]): void;
        };
        error: {
            (...data: any[]): void;
            (...data: any[]): void;
        };
    } | null;
};
//# sourceMappingURL=state.d.ts.map