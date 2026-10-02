/**
 * Ambient presence — the subtle, safe, never-on-stdout notifier. A port of the
 * Python smokes `tooling/smoke_ambient.py` + `tooling/smoke_ambient_intercept.py`.
 *
 * Proves:
 *   1. cadence resolution (default first_touch; master-off wins; tunes; unknown ->
 *      default; CI / DO_NOT_TRACK suppression unless explicitly on);
 *   2. FIRST_TOUCH dedupe — one line per distinct tool, silent on repeats;
 *   3. EVERY emits each call; SUMMARY emits no per-call lines; OFF emits nothing;
 *   4. CHANNEL SAFETY — across a full run, captured process.stdout is byte-EMPTY;
 *   5. the observer sink receives structured notes; a throwing observer never surfaces;
 *   6. classification parsing (effective_action_type + action_type fallback;
 *      reversible/irreversible/none/destructive; missing -> unknown);
 *   7. honest voice — no green/safety word in any emitted line;
 *   8. the session summary carries the counts and is silent when nothing was watched;
 *   9. wired into wrap(): default-on, observer reaches on_invocation, the close hook
 *      emits the summary, and the gate's return value is untouched.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  AmbientMode,
  AmbientNotifier,
  resolveMode,
  type AmbientNote,
  type WritableLike,
} from "../src/ambient.js";
import { wrap, PreflightHold } from "../src/wrap.js";
import { PreflightPin } from "../src/preflight.js";

/** An in-memory `process.stderr`-like sink the notifier can write to under test. */
class Capture implements WritableLike {
  buf = "";
  write(chunk: string): boolean {
    this.buf += chunk;
    return true;
  }
  lines(): string[] {
    return this.buf.split("\n").filter((l) => l.trim() !== "");
  }
}

const GREEN = ["protected", "secured", " safe ", "safe.", "guaranteed", "blocked it"];

function noGreen(text: string): boolean {
  const low = ` ${text.toLowerCase()} `;
  return !GREEN.some((g) => low.includes(g));
}

// ---------------------------------------------------------------- resolveMode
test("resolveMode: default first_touch; master-off wins; tunes + unknown; CI/DO_NOT_TRACK", () => {
  assert.equal(resolveMode({}), AmbientMode.FIRST_TOUCH);
  assert.equal(resolveMode({ MCPINDEX_AMBIENT_NOTICE: "off" }), AmbientMode.OFF);
  assert.equal(resolveMode({ MCPINDEX_AMBIENT_NOTICE: "0" }), AmbientMode.OFF);
  assert.equal(resolveMode({ MCPINDEX_AMBIENT_NOTICE_MODE: "summary" }), AmbientMode.SUMMARY);
  assert.equal(resolveMode({ MCPINDEX_AMBIENT_NOTICE_MODE: "every" }), AmbientMode.EVERY);
  assert.equal(resolveMode({ MCPINDEX_AMBIENT_NOTICE_MODE: "nonsense" }), AmbientMode.FIRST_TOUCH);
  // master-off beats a per-call tune
  assert.equal(
    resolveMode({ MCPINDEX_AMBIENT_NOTICE: "false", MCPINDEX_AMBIENT_NOTICE_MODE: "every" }),
    AmbientMode.OFF,
  );
  // CI / DO_NOT_TRACK auto-quiet unless explicitly on
  assert.equal(resolveMode({ CI: "true" }), AmbientMode.OFF);
  assert.equal(resolveMode({ CI: "1" }), AmbientMode.OFF);
  assert.equal(resolveMode({ DO_NOT_TRACK: "1" }), AmbientMode.OFF);
  assert.equal(resolveMode({ DO_NOT_TRACK: "" }), AmbientMode.OFF); // presence, not value
  // a falsey CI does NOT suppress
  assert.equal(resolveMode({ CI: "0" }), AmbientMode.FIRST_TOUCH);
  assert.equal(resolveMode({ CI: "false" }), AmbientMode.FIRST_TOUCH);
  // explicit master-on overrides CI / DO_NOT_TRACK suppression
  assert.equal(resolveMode({ CI: "true", MCPINDEX_AMBIENT_NOTICE: "1" }), AmbientMode.FIRST_TOUCH);
  // the master switch only gates on/off (an "every"/"summary" VALUE still counts as
  // explicit-on but the CADENCE comes from MCPINDEX_AMBIENT_NOTICE_MODE) — faithful to Python
  assert.equal(
    resolveMode({ CI: "true", MCPINDEX_AMBIENT_NOTICE: "every" }),
    AmbientMode.FIRST_TOUCH,
  );
  assert.equal(
    resolveMode({ CI: "true", MCPINDEX_AMBIENT_NOTICE: "1", MCPINDEX_AMBIENT_NOTICE_MODE: "every" }),
    AmbientMode.EVERY,
  );
  assert.equal(
    resolveMode({ DO_NOT_TRACK: "1", MCPINDEX_AMBIENT_NOTICE: "1", MCPINDEX_AMBIENT_NOTICE_MODE: "summary" }),
    AmbientMode.SUMMARY,
  );
});

// ---------------------------------------------------------------- first-touch
test("FIRST_TOUCH: one line per distinct tool; repeats are silent", () => {
  const err = new Capture();
  const n = new AmbientNotifier({ mode: AmbientMode.FIRST_TOUCH, stderr: err });
  n.noteInvocation("gh", "create_issue", { action_type: "write", reversibility: "reversible" });
  n.noteInvocation("gh", "create_issue", { action_type: "write" }); // repeat -> silent
  n.noteInvocation("gh", "delete_repo", { action_type: "delete", reversibility: "irreversible" });
  const lines = err.lines();
  assert.equal(lines.length, 2, `expected 2 lines, got ${JSON.stringify(lines)}`);
  assert.ok(lines[0].includes("create_issue") && lines[0].includes("reversible"));
  assert.ok(lines[1].includes("delete_repo") && lines[1].includes("irreversible"));
  // the exact format: middle dot + em dash
  assert.ok(lines[0].startsWith("mcpindex · noted gh/create_issue — "));
});

// ----------------------------------------------------------- every & summary
test("EVERY emits each call; SUMMARY emits only the footer with counts", () => {
  const errE = new Capture();
  const ne = new AmbientNotifier({ mode: AmbientMode.EVERY, stderr: errE });
  for (let i = 0; i < 3; i++) ne.noteInvocation("gh", "create_issue", { action_type: "write" });
  assert.equal(errE.lines().length, 3);

  const errS = new Capture();
  const ns = new AmbientNotifier({ mode: AmbientMode.SUMMARY, stderr: errS });
  ns.noteInvocation("gh", "create_issue", { action_type: "write" });
  ns.noteInvocation("gh", "delete_repo", { action_type: "delete" });
  assert.equal(errS.buf.trim(), "", "summary-mode must emit NO per-call lines");
  const summary = ns.sessionSummary({ drift: 1, flagged: 2 });
  assert.ok(summary !== null);
  assert.ok(summary.includes("2 tool(s)") && summary.includes("1 drift") && summary.includes("2 flagged"));
  assert.ok(summary.includes("mcpindex.ai"));
});

test("summary omits counts when not both passed", () => {
  const err = new Capture();
  const n = new AmbientNotifier({ mode: AmbientMode.FIRST_TOUCH, stderr: err });
  n.noteInvocation("gh", "x", { action_type: "read" });
  const onlyDrift = n.sessionSummary({ drift: 5 });
  assert.ok(onlyDrift !== null);
  assert.ok(!onlyDrift.includes("drift"), `counts must be omitted unless BOTH passed: ${onlyDrift}`);
});

// ------------------------------------------------------------------------ off
test("OFF: nothing emitted, note + summary return null", () => {
  const err = new Capture();
  const n = new AmbientNotifier({ mode: AmbientMode.OFF, stderr: err });
  const r = n.noteInvocation("gh", "create_issue", { action_type: "write" });
  const s = n.sessionSummary();
  assert.equal(r, null);
  assert.equal(s, null);
  assert.equal(err.buf.trim(), "");
  assert.equal(n.enabled, false);
});

// -------------------------------------------------------------- channel safety
test("CHANNEL SAFETY: process.stdout stays byte-EMPTY; the signal is on stderr only", () => {
  // Default-stderr notifier (process.stderr) — capture process.stdout across the run and
  // assert it is byte-empty. This is the load-bearing protocol guard.
  const origStdout = process.stdout.write.bind(process.stdout);
  const origStderr = process.stderr.write.bind(process.stderr);
  let stdoutBytes = "";
  let stderrBytes = "";
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  process.stdout.write = ((chunk: any): boolean => {
    stdoutBytes += String(chunk);
    return true;
  }) as typeof process.stdout.write;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  process.stderr.write = ((chunk: any): boolean => {
    stderrBytes += String(chunk);
    return true;
  }) as typeof process.stderr.write;
  try {
    const n = new AmbientNotifier({ mode: AmbientMode.EVERY }); // default stderr = process.stderr
    for (let i = 0; i < 5; i++) n.noteInvocation(`srv${i}`, "do_thing", { action_type: "write" });
    n.sessionSummary({ drift: 0, flagged: 0 });
  } finally {
    process.stdout.write = origStdout;
    process.stderr.write = origStderr;
  }
  assert.equal(stdoutBytes, "", `CHANNEL SAFETY VIOLATION: ambient wrote to stdout: ${JSON.stringify(stdoutBytes)}`);
  assert.ok(stderrBytes.trim() !== "", "expected the ambient lines on stderr");
});

// --------------------------------------------------------------- observer
test("observer: receives structured notes; a throwing observer never surfaces", () => {
  const seen: AmbientNote[] = [];
  const n = new AmbientNotifier({
    mode: AmbientMode.FIRST_TOUCH,
    stderr: new Capture(),
    observer: (note) => seen.push(note),
  });
  n.noteInvocation("gh", "create_issue", { action_type: "write", reversibility: "reversible" });
  assert.equal(seen.length, 1);
  assert.equal(seen[0].toolName, "create_issue");
  assert.equal(seen[0].action, "write");
  assert.equal(seen[0].reversible, "reversible");

  const boom: AmbientNotifier = new AmbientNotifier({
    mode: AmbientMode.FIRST_TOUCH,
    stderr: new Capture(),
    observer: () => {
      throw new Error("integrator UI crashed");
    },
  });
  // must NOT throw — a broken observer is the integrator's bug, never the gate's
  const got = boom.noteInvocation("gh", "x", { action_type: "read" });
  assert.ok(got !== null, "a throwing observer must not suppress the note emit");
});

// ----------------------------------------------------- classification + honesty
test("classification parsed (effective_action_type + fallback + reversibility); lines stay advisory", () => {
  const n = new AmbientNotifier({ mode: AmbientMode.FIRST_TOUCH, stderr: new Capture() });

  const miss = n.buildNote("s", "t");
  assert.equal(miss.action, "unknown");
  assert.equal(miss.reversible, "unknown");

  // effective_action_type wins over action_type
  const eff = n.buildNote("s", "t2", { effective_action_type: "delete", action_type: "write", reversibility: "irreversible" });
  assert.equal(eff.action, "delete");
  assert.equal(eff.reversible, "irreversible");

  // action_type is the fallback when effective_action_type is absent
  const fb = n.buildNote("s", "t3", { action_type: "write", reversibility: "reversible" });
  assert.equal(fb.action, "write");
  assert.equal(fb.reversible, "reversible");

  // reversibility mapping: the real enum values (reversible | hard-to-reverse | irreversible)
  assert.equal(n.buildNote("s", "a", { reversibility: "hard-to-reverse" }).reversible, "hard-to-reverse");
  assert.equal(n.buildNote("s", "b", { reversibility: "irreversible" }).reversible, "irreversible");
  // an unrecognized non-empty reversibility -> unknown
  assert.equal(n.buildNote("s", "c", { reversibility: "weird" }).reversible, "unknown");

  for (const note of [miss, eff, fb]) {
    assert.ok(noGreen(note.text), `ambient line must stay advisory (no green word): ${note.text}`);
  }
});

test("summary: silent when nothing was watched", () => {
  const n = new AmbientNotifier({ mode: AmbientMode.FIRST_TOUCH, stderr: new Capture() });
  assert.equal(n.sessionSummary(), null);
});

// ============================================================ wrap() integration
/** A minimal fake MCP session: records callTool so we can prove gate parity and
 * that the wrapped session's return value is untouched. */
class FakeSession {
  callLog: string[] = [];
  closed = false;
  constructor(private tools: Array<Record<string, unknown>>) {}
  setTools(tools: Array<Record<string, unknown>>): void {
    this.tools = tools;
  }
  async listTools(): Promise<{ tools: Array<Record<string, unknown>> }> {
    return { tools: [...this.tools] };
  }
  async callTool(params: { name: string; arguments?: Record<string, unknown> }): Promise<{ ok: boolean; tool: string }> {
    this.callLog.push(params.name);
    return { ok: true, tool: params.name };
  }
  async close(): Promise<void> {
    this.closed = true;
  }
}

const READ_TOOL = {
  name: "list_files",
  description: "list files in a directory",
  inputSchema: { type: "object", properties: { path: { type: "string" } } },
};
const DELETE_TOOL = {
  name: "delete_file",
  description: "permanently delete a file at a path",
  inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },
};

test("wrap(): ambient default-on, observer wired, stdout byte-EMPTY, return value untouched", async () => {
  const prev = process.env.MCPINDEX_AMBIENT_NOTICE;
  process.env.MCPINDEX_AMBIENT_NOTICE = "first_touch"; // force on (CI would otherwise suppress)

  const origStdout = process.stdout.write.bind(process.stdout);
  let stdoutBytes = "";
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  process.stdout.write = ((chunk: any): boolean => {
    stdoutBytes += String(chunk);
    return true;
  }) as typeof process.stdout.write;

  const notes: AmbientNote[] = [];
  try {
    const sess = new FakeSession([READ_TOOL, DELETE_TOOL]);
    const w = wrap(sess, {
      pin: new PreflightPin(),
      serverId: "srv",
      onInvocation: (note) => notes.push(note),
    });
    await w.listTools(); // TOFU pin
    const r1 = await w.callTool({ name: "list_files", arguments: { path: "/x" } });
    await w.callTool({ name: "list_files", arguments: { path: "/y" } }); // repeat -> silent
    await w.callTool({ name: "delete_file", arguments: { path: "/z" } });
    // return value is exactly the wrapped session's
    assert.deepEqual(r1, { ok: true, tool: "list_files" });
    assert.deepEqual(sess.callLog, ["list_files", "list_files", "delete_file"]);
  } finally {
    process.stdout.write = origStdout;
    if (prev === undefined) delete process.env.MCPINDEX_AMBIENT_NOTICE;
    else process.env.MCPINDEX_AMBIENT_NOTICE = prev;
  }

  assert.equal(stdoutBytes, "", `CHANNEL SAFETY VIOLATION via wrap(): ${JSON.stringify(stdoutBytes)}`);
  // first-touch: one note per distinct tool
  assert.equal(notes.length, 2, `expected 2 notes (one per distinct tool), got ${notes.length}`);
  assert.deepEqual(notes.map((n) => n.toolName), ["list_files", "delete_file"]);
});

test("wrap(): the close() hook emits the session summary, then delegates to the real close", async () => {
  const prev = process.env.MCPINDEX_AMBIENT_NOTICE;
  process.env.MCPINDEX_AMBIENT_NOTICE = "first_touch";

  const origStderr = process.stderr.write.bind(process.stderr);
  let stderrBytes = "";
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  process.stderr.write = ((chunk: any): boolean => {
    stderrBytes += String(chunk);
    return true;
  }) as typeof process.stderr.write;

  let sess: FakeSession;
  try {
    sess = new FakeSession([READ_TOOL]);
    const w = wrap(sess, { pin: new PreflightPin(), serverId: "srv" });
    await w.listTools();
    await w.callTool({ name: "list_files", arguments: { path: "/x" } });
    await (w as unknown as { close(): Promise<void> }).close();
  } finally {
    process.stderr.write = origStderr;
    if (prev === undefined) delete process.env.MCPINDEX_AMBIENT_NOTICE;
    else process.env.MCPINDEX_AMBIENT_NOTICE = prev;
  }
  assert.ok(stderrBytes.includes("noted 1 tool"), `summary must emit on close: ${stderrBytes}`);
  assert.ok(stderrBytes.includes("mcpindex.ai"));
  assert.equal(sess!.closed, true, "the real close must still run");
});

test("wrap(): a HOLD never emits an ambient line and never reaches the session", async () => {
  const prev = process.env.MCPINDEX_AMBIENT_NOTICE;
  process.env.MCPINDEX_AMBIENT_NOTICE = "first_touch";

  const notes: AmbientNote[] = [];
  try {
    const sess = new FakeSession([READ_TOOL]);
    const w = wrap(sess, {
      pin: new PreflightPin(),
      serverId: "srv",
      onInvocation: (note) => notes.push(note),
    });
    await w.listTools(); // pin the safe contract
    // drift the contract: add a required param (a HOLD-worthy change)
    sess.setTools([
      {
        name: "list_files",
        description: "list files in a directory",
        inputSchema: {
          type: "object",
          properties: { path: { type: "string" } },
          required: ["path", "token"],
        },
      },
    ]);
    await w.listTools(); // observe drift (no re-pin)
    await assert.rejects(
      () => w.callTool({ name: "list_files", arguments: { path: "/x" } }),
      PreflightHold,
    );
    assert.equal(notes.length, 0, "a HELD call must NOT emit an ambient note");
    assert.deepEqual(sess.callLog, [], "the wrapped session must never be called on a HOLD");
  } finally {
    if (prev === undefined) delete process.env.MCPINDEX_AMBIENT_NOTICE;
    else process.env.MCPINDEX_AMBIENT_NOTICE = prev;
  }
});

test("sanitizes a hostile tool name (no log injection) + bounds length", () => {
  const n = new AmbientNotifier({ mode: AmbientMode.EVERY, stderr: new Capture() });
  const note = n.buildNote("srv", "evil\x1b[2Ktool\nmcpindex · watching srv/FAKE", { action_type: "read" });
  for (const bad of ["\x1b", "\n", "\r"]) {
    assert.ok(!note.text.includes(bad), `control char must be stripped: ${JSON.stringify(note.text)}`);
  }
  assert.ok(note.text.includes("evil") && note.text.includes("tool"));
  const long = n.buildNote("srv", "x".repeat(5000), undefined);
  assert.ok(long.text.length <= 320, `line must be length-bounded, got ${long.text.length}`);
});
