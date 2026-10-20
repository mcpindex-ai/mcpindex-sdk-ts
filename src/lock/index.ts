/**
 * `@mcp-index/sdk/lock`: lock mode (mcp.lock draft 1). Opt-in; nothing here
 * runs unless a host constructs it. The root `@mcp-index/sdk` import does not
 * load this module. The Postgres store is a separate subpath,
 * `@mcp-index/sdk/lock/pg`.
 */

export {
  CanonicalizationError,
  DIGEST_PREFIX,
  NUMBER_LIMIT,
  canonicalBody,
  canonicalize,
  hasLoneSurrogate,
  instructionsDigest,
  toolDigest,
  toolSetDigest,
} from "./digest.js";
export {
  ALIASES,
  FrozenMap,
  LOCK_VERSION,
  LockError,
  MANIFEST,
  POSTURES,
  REGISTRIES,
  SIGNATURE,
  commandIdentity,
  findDuplicateKey,
  formatAliases,
  formatLockFile,
  formatManifest,
  formatShard,
  identityH16,
  identityKey,
  loadLock,
  normalizeUrl,
  packageIdentity,
  parseShard,
  remoteIdentity,
  resolveAlias,
  shardFilename,
  slug,
  strictJson,
  validateIdentity,
} from "./lock.js";
export type {
  Approval,
  Attributes,
  CommandIdentity,
  Identity,
  LoadedLock,
  Lock,
  LockErrorReason,
  ManifestVerifier,
  PackageIdentity,
  Posture,
  ReaderConfig,
  RemoteIdentity,
  Shard,
  SignerIdentity,
  ToolEntry,
  Via,
} from "./lock.js";
export {
  CallGate,
  LOCK_REFUSAL_CODE,
  LOCK_REFUSAL_MESSAGE,
  LockRefusal,
  checkCall,
  checkInstructions,
  checkListing,
  isPosture,
  refusalError,
} from "./check.js";
export type { CallGateOptions, CallReason, Decision, Listing, RefusalError, ToolOutcome, ToolReason } from "./check.js";
export { FileLockStore, nowRfc3339, prepareTool, runLockStoreConformance } from "./store.js";
export type {
  ApproveInstructionsRequest,
  ApproveRequest,
  ApproveToolRequest,
  ConformanceOptions,
  ConformanceResult,
  FileLockStoreOptions,
  LockSnapshot,
  LockStore,
  RevokeRequest,
} from "./store.js";
export { EVENT_SCHEMA, approvalEvent, jsonlFileSink, listingEvent, refusalEvent } from "./events.js";
export type { ApprovalEvent, EventContext, ListingEvent, LockEvent, LockEventSink, RefusalEvent } from "./events.js";
export { LockedTransport, MAX_LIST_PAGES, MAX_LIST_TOOLS, lockClient } from "./rawList.js";
export type { ConnectableClient, LockOptions } from "./rawList.js";
export { anchoredPattern, sigstoreVerifier } from "./signing.js";
export type { SigstoreVerifierOptions } from "./signing.js";
