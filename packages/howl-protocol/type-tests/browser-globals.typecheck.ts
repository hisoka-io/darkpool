export {};

// @ts-expect-error Node ambient types must stay outside the browser boundary.
type _ProcessAbsent = typeof process;

// @ts-expect-error Node ambient types must stay outside the browser boundary.
type _BufferAbsent = typeof Buffer;

// @ts-expect-error DOM ambient types must stay outside the browser boundary.
type _DocumentAbsent = typeof document;
