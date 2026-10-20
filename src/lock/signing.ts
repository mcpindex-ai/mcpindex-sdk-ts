/**
 * Manifest signature verification (section 8.2).
 *
 * The signer identity and the trust root come from the host's own config
 * object. Nothing here reads the lock repository or the environment for
 * either. `sigstore` is an optional peer dependency, loaded on the verify
 * path only; when it is missing, verify returns false and the reader fails
 * with lock-signature-invalid, as it does for a missing or bad bundle.
 *
 * Verification is offline against a trusted_root.json the operator supplies.
 * The issuer and SAN are matched exactly: sigstore treats the SAN policy as a
 * regular expression, so it gets an escaped, anchored pattern, and the signer
 * it returns is compared again by plain string equality.
 */

import { lstatSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";

import type { ManifestVerifier, SignerIdentity } from "./lock.js";

export type { ManifestVerifier, SignerIdentity } from "./lock.js";

export interface SigstoreVerifierOptions {
  /** Path to a Sigstore trusted_root.json, from host configuration. */
  readonly trustedRootPath: string;
  /** Transparency log entries required (sigstore default 1). */
  readonly tlogThreshold?: number;
  /** Certificate transparency entries required (sigstore default 1). */
  readonly ctlogThreshold?: number;
  /** Module loader, for tests. Defaults to resolving `sigstore` from this package. */
  readonly load?: (name: string) => unknown;
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
}

/** Exact, anchored pattern for sigstore's regex-based SAN policy. */
export function anchoredPattern(text: string): string {
  return `^${escapeRegExp(text)}$`;
}

function readTrustedRoot(path: string): unknown {
  const st = lstatSync(path);
  if (st.isSymbolicLink() || !st.isFile()) throw new Error("trusted root is not a regular file");
  return JSON.parse(readFileSync(path, "utf8")) as unknown;
}

function defaultLoader(): (name: string) => unknown {
  const here = createRequire(import.meta.url);
  // Resolve the @sigstore/* parts from sigstore's own location, so this works
  // whether or not the package manager hoists them.
  const main = here.resolve("sigstore");
  const fromSigstore = createRequire(main);
  return (name: string) => (name === "sigstore" ? here(main) : fromSigstore(name));
}

interface SigstoreParts {
  bundleFromJSON(json: unknown): unknown;
  toSignedEntity(bundle: unknown, data: Buffer): unknown;
  toTrustMaterial(root: unknown): unknown;
  Verifier: new (trust: unknown, options: Record<string, unknown>) => {
    verify(entity: unknown, policy: Record<string, unknown>): {
      identity?: { subjectAlternativeName?: string; extensions?: { issuer?: string } };
    };
  };
  TrustedRoot: { fromJSON(json: unknown): unknown };
}

function loadParts(load: (name: string) => unknown): SigstoreParts {
  load("sigstore"); // presence check for the declared peer
  const verify = load("@sigstore/verify") as Record<string, unknown>;
  const bundle = load("@sigstore/bundle") as Record<string, unknown>;
  const specs = load("@sigstore/protobuf-specs") as Record<string, unknown>;
  return {
    bundleFromJSON: bundle.bundleFromJSON as SigstoreParts["bundleFromJSON"],
    toSignedEntity: verify.toSignedEntity as SigstoreParts["toSignedEntity"],
    toTrustMaterial: verify.toTrustMaterial as SigstoreParts["toTrustMaterial"],
    Verifier: verify.Verifier as SigstoreParts["Verifier"],
    TrustedRoot: specs.TrustedRoot as SigstoreParts["TrustedRoot"],
  };
}

/**
 * Sigstore verifier for MANIFEST.json. Returns false (never throws) on a
 * missing module, unreadable trust root, malformed bundle, failed signature,
 * or a signer that differs from the configured issuer and SAN.
 */
export function sigstoreVerifier(options: SigstoreVerifierOptions): ManifestVerifier {
  return {
    async verify(manifest: Uint8Array, bundle: Uint8Array, signer: SignerIdentity): Promise<boolean> {
      try {
        if (typeof signer.issuer !== "string" || typeof signer.san !== "string" || !signer.issuer || !signer.san) {
          return false;
        }
        const parts = loadParts(options.load ?? defaultLoader());
        const root = parts.TrustedRoot.fromJSON(readTrustedRoot(options.trustedRootPath));
        const trust = parts.toTrustMaterial(root);
        const verifier = new parts.Verifier(trust, {
          tlogThreshold: options.tlogThreshold ?? 1,
          ctlogThreshold: options.ctlogThreshold ?? 1,
        });
        const parsed = parts.bundleFromJSON(JSON.parse(Buffer.from(bundle).toString("utf8")) as unknown);
        const entity = parts.toSignedEntity(parsed, Buffer.from(manifest));
        const result = verifier.verify(entity, {
          subjectAlternativeName: anchoredPattern(signer.san),
          extensions: { issuer: signer.issuer },
        });
        const identity = result?.identity;
        return identity?.subjectAlternativeName === signer.san && identity?.extensions?.issuer === signer.issuer;
      } catch {
        return false;
      }
    },
  };
}
