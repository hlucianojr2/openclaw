export type ClearSessionQueueResult = {
    followupCleared: number;
    laneCleared: number;
    keys: string[];
};
export declare function clearSessionQueues(keys: Array<string | undefined>): ClearSessionQueueResult;
//# sourceMappingURL=cleanup.d.ts.map