import type { PluginRuntime } from "openclaw/plugin-sdk/signal";
import { createPluginRuntimeStore } from "openclaw/plugin-sdk";

const { setRuntime: setSignalRuntime, getRuntime: getSignalRuntime } =
  createPluginRuntimeStore<PluginRuntime>("Signal runtime not initialized");
export { getSignalRuntime, setSignalRuntime };
