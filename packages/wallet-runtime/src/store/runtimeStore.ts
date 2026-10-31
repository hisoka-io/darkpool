import { deploymentKey, type DeploymentRef } from "@hisoka/howl-protocol";

/** Local durable key-value storage. `set` and `setMany` resolve only once the write is durable. */
export interface RuntimeStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  /** One atomic batch; a `null` value deletes the key. */
  setMany(
    entries: readonly (readonly [string, string | null])[],
  ): Promise<void>;
}

/** Keys are namespaced per deployment, so two pools (or a redeploy) never read each other's state. */
export function runtimeKey(
  deployment: DeploymentRef,
  ...parts: readonly string[]
): string {
  return ["hisoka.runtime.v1", deploymentKey(deployment), ...parts].join(".");
}
