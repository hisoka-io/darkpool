// Reached only by logger colour detection. A browser build has no tty.
export const isatty = () => false;
export default { isatty };
