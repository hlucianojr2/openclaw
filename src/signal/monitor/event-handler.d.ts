import type { SignalEventHandlerDeps } from "./event-handler.types.js";
export declare function createSignalEventHandler(deps: SignalEventHandlerDeps): (event: {
    event?: string | undefined;
    data?: string | undefined;
}) => Promise<void>;
//# sourceMappingURL=event-handler.d.ts.map