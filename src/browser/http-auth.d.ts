import type { IncomingMessage } from "node:http";
export declare function isAuthorizedBrowserRequest(req: IncomingMessage, auth: {
    token?: string;
    password?: string;
}): boolean;
//# sourceMappingURL=http-auth.d.ts.map