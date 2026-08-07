export const COLLECTIONS = ["state", "labels"] as const;

export type Collection = (typeof COLLECTIONS)[number];

export function isCollection(value: unknown): value is Collection {
  return (
    typeof value === "string" &&
    (COLLECTIONS as readonly string[]).includes(value)
  );
}
