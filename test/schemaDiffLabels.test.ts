// Label-only change kinds (title-changed, annotation-hint-changed). The pairs are a
// byte-identical copy of mcpindex-trust tests/fixtures/schema_diff_label_pairs.json; each
// carries what classifyChange and classifyLabelChanges must return and the gate decisions
// recorded before these kinds existed, except the two cases where a title or hint moves
// beside an added optional parameter, re-recorded when that stopped being auto-accepted.
// crossLangParity.test.ts runs the same pairs through live Python.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Gate, GUARD_DANGEROUS_KINDS, Posture, DEFAULT_BEHAVIORAL_MANDATED_KINDS } from "../src/gate.js";
import { PreflightPin, type ToolDef } from "../src/preflight.js";
import {
  ChangeKind,
  classifyChange,
  classifyLabelChanges,
  isSafetyRelevant,
  LABEL_ONLY_KINDS,
} from "../src/schemaDiff.js";
import * as sdk from "../src/index.js";

interface Pair {
  case: string;
  before: ToolDef;
  after: ToolDef;
  kinds: string[];
  labels: Array<{ kind: string; path: string; detail: string }>;
  gate: Record<string, { static: string; effective: string }>;
}

const here = dirname(fileURLToPath(import.meta.url));
const pairs: Pair[] = JSON.parse(
  readFileSync(join(here, "../../test/fixtures/schema-diff-label-pairs.json"), "utf8"),
).pairs;
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;

test("label-only kinds: two members, not safety-relevant, exported", () => {
  assert.equal(ChangeKind.ANNOTATION_HINT_CHANGED, "annotation-hint-changed");
  assert.equal(ChangeKind.TITLE_CHANGED, "title-changed");
  assert.deepEqual([...LABEL_ONLY_KINDS].sort(), ["annotation-hint-changed", "title-changed"]);
  for (const k of LABEL_ONLY_KINDS) assert.equal(isSafetyRelevant(k), false, k);
  assert.equal(sdk.classifyLabelChanges, classifyLabelChanges);
  assert.equal(sdk.LABEL_ONLY_KINDS, LABEL_ONLY_KINDS);
});

test("label-only kinds are in no gate set", () => {
  for (const k of LABEL_ONLY_KINDS) {
    assert.ok(!GUARD_DANGEROUS_KINDS.has(k), `guard set has ${k}`);
    assert.ok(!DEFAULT_BEHAVIORAL_MANDATED_KINDS.has(k), `mandated set has ${k}`);
  }
  // BENIGN_AUTOACCEPT_KINDS and BREAKING_KIND_REASON are module-private; read the source.
  const src = readFileSync(join(here, "../../src/gate.ts"), "utf8");
  assert.ok(!/ANNOTATION_HINT_CHANGED|TITLE_CHANGED|annotation-hint-changed|title-changed/.test(src), "gate.ts names a label-only kind");
});

test("each pair: classifyLabelChanges emits the recorded labels", () => {
  assert.ok(pairs.length >= 30, `fixture shrank to ${pairs.length}`);
  for (const p of pairs) {
    const got = classifyLabelChanges(clone(p.before), clone(p.after)).map((c) => ({ kind: c.kind, path: c.path, detail: c.detail }));
    assert.deepEqual(got, p.labels, p.case);
    for (const c of classifyLabelChanges(p.before, p.after)) {
      assert.ok(LABEL_ONLY_KINDS.has(c.kind) && !c.safetyRelevant, `${p.case}: ${JSON.stringify(c)}`);
    }
  }
});

test("each pair: classifyChange is unchanged and never emits a label-only kind", () => {
  for (const p of pairs) {
    const kinds = classifyChange(clone(p.before), clone(p.after)).map((c) => c.kind as string);
    assert.deepEqual(kinds, p.kinds, p.case);
    assert.ok(!kinds.some((k) => LABEL_ONLY_KINDS.has(k as ChangeKind)), p.case);
  }
});

test("classifyLabelChanges is total on hostile input", () => {
  let deep: unknown = true;
  for (let i = 0; i < 200; i++) deep = { x: deep };
  const cases: Array<[Record<string, unknown>, Record<string, unknown>, string[]]> = [
    [{}, {}, []],
    [{ annotations: null }, { annotations: [] }, []],
    [{ title: 3 }, { title: "3" }, ["title-changed"]],
    [{ annotations: { readOnlyHint: deep } }, { annotations: { readOnlyHint: deep } }, ["annotation-hint-changed"]],
    [{ annotations: { title: ["a"] } }, { annotations: { title: ["a"] } }, []],
  ];
  for (const [a, b, want] of cases) {
    assert.deepEqual(classifyLabelChanges(a, b).map((c) => c.kind as string), want);
  }
});

test("each pair: gate decisions match the recording under monitor, guard and strict", () => {
  for (const p of pairs) {
    for (const posture of [Posture.MONITOR, Posture.GUARD, Posture.STRICT]) {
      const gate = new Gate({ pin: new PreflightPin(), serverId: "srv", posture });
      gate.observe(String(p.before.name), clone(p.before));
      const [stat, eff] = gate.assess(String(p.after.name), clone(p.after));
      assert.deepEqual({ static: stat.decision, effective: eff.decision }, p.gate[posture], `${p.case} ${posture}`);
      for (const v of [stat, eff]) {
        assert.ok(!v.drift.some((c) => LABEL_ONLY_KINDS.has(c.kind)), `${p.case} ${posture}: label kind in verdict`);
      }
    }
  }
});

test("a title or hint beside an added optional parameter holds and keeps the pin", () => {
  for (const name of ["hint-plus-optional-param", "title-plus-optional-param"]) {
    const p = pairs.find((x) => x.case === name)!;
    assert.deepEqual(p.kinds, ["added-optional-param"], name);
    assert.ok(p.labels.length > 0, name);
    for (const posture of [Posture.MONITOR, Posture.GUARD, Posture.STRICT]) {
      const pin = new PreflightPin();
      const gate = new Gate({ pin, serverId: "srv", posture });
      gate.observe(String(p.before.name), clone(p.before));
      const before = pin.get("srv", String(p.before.name))!.definitionHash;
      const [stat, eff] = gate.decide(String(p.after.name), clone(p.after));
      assert.equal(stat.decision, "HOLD", `${name} ${posture}`);
      assert.ok(stat.reason.includes("title or annotation hint changed"), stat.reason);
      for (const lab of p.labels) assert.ok(stat.reason.includes(lab.path), `${name}: ${lab.path}`);
      assert.equal(eff.decision, posture === Posture.MONITOR ? "PROCEED" : "HOLD", `${name} ${posture}`);
      assert.equal(pin.get("srv", String(p.before.name))!.definitionHash, before, `${name} ${posture}: pin moved`);
    }
    // The same parameter with no label change still auto-accepts.
    const plain = clone(p.after) as Record<string, unknown>;
    delete plain["title"];
    delete plain["annotations"];
    const gate = new Gate({ pin: new PreflightPin(), serverId: "srv", posture: Posture.GUARD });
    gate.observe(String(p.before.name), clone(p.before));
    const [stat] = gate.decide(String(plain["name"]), plain as ToolDef);
    assert.equal(stat.decision, "PROCEED", name);
    assert.ok(stat.reason.includes("PROVEN BENIGN"), stat.reason);
  }
});
