import type { PluginRuntime } from "openclaw/plugin-sdk/zalouser";
import { createPluginRuntimeStore } from "openclaw/plugin-sdk";

const { setRuntime: setZalouserRuntime, getRuntime: getZalouserRuntime } =
  createPluginRuntimeStore<PluginRuntime>("Zalouser runtime not initialized");
export { getZalouserRuntime, setZalouserRuntime };
