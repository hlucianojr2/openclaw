import type { AnyAgentTool } from "./common.js";
import { type GatewayMessageChannel } from "../../utils/message-channel.js";
export declare function createSessionsSendTool(opts?: {
    agentSessionKey?: string;
    agentChannel?: GatewayMessageChannel;
    sandboxed?: boolean;
}): AnyAgentTool;
//# sourceMappingURL=sessions-send-tool.d.ts.map