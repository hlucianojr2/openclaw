import type { ReplyPayload } from "../types.js";
import type { TypingSignaler } from "./typing-mode.js";
import { type VerboseLevel } from "../thinking.js";
export declare const isAudioPayload: (payload: ReplyPayload) => boolean;
export declare const createShouldEmitToolResult: (params: {
    sessionKey?: string | undefined;
    storePath?: string | undefined;
    resolvedVerboseLevel: VerboseLevel;
}) => () => boolean;
export declare const createShouldEmitToolOutput: (params: {
    sessionKey?: string | undefined;
    storePath?: string | undefined;
    resolvedVerboseLevel: VerboseLevel;
}) => () => boolean;
export declare const finalizeWithFollowup: <T>(value: T, queueKey: string, runFollowupTurn: (run: import("./queue.js").FollowupRun) => Promise<void>) => T;
export declare const signalTypingIfNeeded: (payloads: ReplyPayload[], typingSignals: TypingSignaler) => Promise<void>;
//# sourceMappingURL=agent-runner-helpers.d.ts.map