/** Raw revert data of a call that must revert; for errors no ABI in reach declares, matched as bytes. */
export async function revertData(call: Promise<unknown>): Promise<string> {
  try {
    await call;
  } catch (error) {
    const data = (error as { data?: unknown }).data;
    if (typeof data === "string") return data;
    throw new Error(`call reverted without revert data: ${String(error)}`);
  }
  throw new Error("call did not revert");
}
