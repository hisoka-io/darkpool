import { today } from "./migrate.js";

const MS_PER_DAY = 86_400_000;

// The TTL anchor is a date, so a sweep can never fire more usefully than once per date.
export const SWEEP_INTERVAL_MS = MS_PER_DAY;

export function retentionCutoff(now: Date, retentionDays: number): string {
  return today(new Date(now.getTime() - retentionDays * MS_PER_DAY));
}
