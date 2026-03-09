import type { PluginRuntime } from "openclaw/plugin-sdk/tlon";
import { createPluginRuntimeStore } from "openclaw/plugin-sdk";

const { setRuntime: setTlonRuntime, getRuntime: getTlonRuntime } =
  createPluginRuntimeStore<PluginRuntime>("Tlon runtime not initialized");
export { getTlonRuntime, setTlonRuntime };
