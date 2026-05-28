/**
 * Internal helpers — exposed for advanced users who need to construct the
 * storage adapter manually (e.g. for custom requireProof middleware in their
 * own routes). Normal usage does NOT need this import.
 */
export { createBetterAuthStorageAdapter } from "./adapter.js";
export type { BetterAuthDbAdapter, BetterAuthInternalAdapter } from "./adapter.js";
