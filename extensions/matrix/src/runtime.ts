import type { PluginRuntime } from "openclaw/plugin-sdk/matrix";
import { createPluginRuntimeStore } from "openclaw/plugin-sdk";

const { setRuntime: setMatrixRuntime, getRuntime: getMatrixRuntime } =
  createPluginRuntimeStore<PluginRuntime>("Matrix runtime not initialized");
export { getMatrixRuntime, setMatrixRuntime };
