import type { PluginRuntime } from "openclaw/plugin-sdk/zalo";
import { createPluginRuntimeStore } from "openclaw/plugin-sdk";

const { setRuntime: setZaloRuntime, getRuntime: getZaloRuntime } =
  createPluginRuntimeStore<PluginRuntime>("Zalo runtime not initialized");
export { getZaloRuntime, setZaloRuntime };
