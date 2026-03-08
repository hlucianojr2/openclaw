export type NativeDependencyHintParams = {
    packageName: string;
    manager?: "pnpm" | "npm" | "yarn";
    rebuildCommand?: string;
    approveBuildsCommand?: string;
    downloadCommand?: string;
};
export declare function formatNativeDependencyHint(params: NativeDependencyHintParams): string;
//# sourceMappingURL=native-deps.d.ts.map