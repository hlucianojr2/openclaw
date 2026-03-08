import type { WebMonitorTuning } from "./types.js";
import { getReplyFromConfig } from "../../auto-reply/reply.js";
import { type RuntimeEnv } from "../../runtime.js";
import { monitorWebInbox } from "../inbound.js";
export declare function monitorWebChannel(verbose: boolean, listenerFactory?: typeof monitorWebInbox  , keepAlive?: boolean, replyResolver?: typeof getReplyFromConfig  , runtime?: RuntimeEnv, abortSignal?: AbortSignal, tuning?: WebMonitorTuning): Promise<void>;
//# sourceMappingURL=monitor.d.ts.map