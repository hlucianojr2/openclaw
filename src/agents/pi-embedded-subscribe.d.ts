import type { SubscribeEmbeddedPiSessionParams } from "./pi-embedded-subscribe.types.js";
export type { BlockReplyChunking, SubscribeEmbeddedPiSessionParams, ToolResultFormat, } from "./pi-embedded-subscribe.types.js";
export declare function subscribeEmbeddedPiSession(params: SubscribeEmbeddedPiSessionParams): {
    assistantTexts: string[];
    toolMetas: {
        toolName?: string | undefined;
        meta?: string | undefined;
    }[];
    unsubscribe: () => void;
    isCompacting: () => boolean;
    isCompactionInFlight: () => boolean;
    getMessagingToolSentTexts: () => string[];
    getMessagingToolSentTargets: () => import("./pi-embedded-messaging.js").MessagingToolSend[];
    didSendViaMessagingTool: () => boolean;
    getLastToolError: () => {
        toolName: string;
        meta?: string | undefined;
        error?: string | undefined;
        mutatingAction?: boolean | undefined;
        actionFingerprint?: string | undefined;
    } | undefined;
    getUsageTotals: () => {
        input: number | undefined;
        output: number | undefined;
        cacheRead: number | undefined;
        cacheWrite: number | undefined;
        total: number | undefined;
    } | undefined;
    getCompactionCount: () => number;
    waitForCompactionRetry: () => Promise<void>;
};
//# sourceMappingURL=pi-embedded-subscribe.d.ts.map