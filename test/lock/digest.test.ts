/**
 * Digest edge cases beyond the vectors: __proto__ survival, surrogates,
 * numbers, Unicode normalization, and the tool set digest sort.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { canonicalBody, canonicalize, instructionsDigest, toolDigest, toolSetDigest } from "../../src/lock/digest.js";

const parse = (text: string): unknown => JSON.parse(text);

test("__proto__ at the top level and nested is covered", () => {
  const plain = parse('{"name":"t","inputSchema":{"type":"object"}}');
  const top = parse('{"name":"t","inputSchema":{"type":"object"},"__proto__":{"a":1}}');
  const deep = parse('{"name":"t","inputSchema":{"type":"object","properties":{"__proto__":{"type":"string"}}}}');
  const d0 = toolDigest(plain);
  const d1 = toolDigest(top);
  const d2 = toolDigest(deep);
  assert.ok(d0 && d1 && d2);
  assert.notEqual(d0, d1);
  assert.notEqual(d0, d2);
  assert.match((canonicalBody(top) as Buffer).toString("utf8"), /"__proto__":\{"a":1\}/);
  assert.match((canonicalBody(deep) as Buffer).toString("utf8"), /"properties":\{"__proto__":\{"type":"string"\}\}/);
  // Plain assignment turns the member into a prototype change and drops it.
  // Spread keeps it (CreateDataProperty). The digest code uses neither.
  const spread = { ...(top as object) };
  assert.equal(Object.keys(spread).includes("__proto__"), true);
  const assigned: Record<string, unknown> = {};
  for (const k of Object.keys(top as object)) assigned[k] = (top as Record<string, unknown>)[k];
  assert.equal(Object.keys(assigned).includes("__proto__"), false);
});

test("top-level _meta is removed, nested _meta is kept", () => {
  const a = toolDigest(parse('{"name":"t","_meta":{"x":1}}'));
  const b = toolDigest(parse('{"name":"t"}'));
  const c = toolDigest(parse('{"name":"t","inputSchema":{"_meta":{"x":1}}}'));
  assert.equal(a, b);
  assert.notEqual(b, c);
});

test("unpaired surrogates in keys or values give no digest; a valid pair does", () => {
  assert.equal(toolDigest(parse('{"name":"t","description":"\\ud800"}')), null);
  assert.equal(toolDigest(parse('{"name":"t","description":"x\\udc00"}')), null);
  assert.equal(toolDigest(parse('{"name":"t","inputSchema":{"\\ud800":1}}')), null);
  assert.equal(toolDigest(parse('{"name":"t","inputSchema":[["\\udbff"]]}')), null);
  assert.ok(toolDigest(parse('{"name":"t","description":"\\ud83d\\ude00"}')));
  // A lone surrogate inside the removed top-level _meta does not matter.
  assert.ok(toolDigest(parse('{"name":"t","_meta":{"\\ud800":"\\udc00"}}')));
  assert.equal(instructionsDigest("a\ud800"), null);
  assert.equal(instructionsDigest(5), null);
});

test("number rule: magnitude at or above 2^53 or non-finite gives no digest", () => {
  assert.equal(toolDigest(parse('{"name":"t","inputSchema":{"maximum":9007199254740992}}')), null);
  assert.equal(toolDigest(parse('{"name":"t","inputSchema":{"maximum":-9007199254740992}}')), null);
  assert.equal(toolDigest(parse('{"name":"t","inputSchema":{"maximum":1e300}}')), null);
  assert.ok(toolDigest(parse('{"name":"t","inputSchema":{"maximum":9007199254740991}}')));
  assert.equal(toolDigest({ name: "t", x: Number.NaN }), null);
  assert.equal(toolDigest({ name: "t", x: Number.POSITIVE_INFINITY }), null);
  assert.equal(canonicalize([-0, 1.5, 1e-7, 0.1]), "[0,1.5,1e-7,0.1]");
});

test("NFC and NFD names are different members and different digests", () => {
  const nfc = toolDigest(parse('{"name":"caf\\u00e9"}'));
  const nfd = toolDigest(parse('{"name":"cafe\\u0301"}'));
  assert.ok(nfc && nfd);
  assert.notEqual(nfc, nfd);
});

test("keys sort by UTF-16 code unit, strings escape as RFC 8785", () => {
  assert.equal(canonicalize(parse('{"\\ue000":1,"\\ud83d\\ude00":2,"b":3,"a":4}')), '{"a":4,"b":3,"\ud83d\ude00":2,"\ue000":1}');
  assert.equal(canonicalize("\u0000\u001f\b\f\n\r\t\"\\/\u007f\u2028"), '"\\u0000\\u001f\\b\\f\\n\\r\\t\\"\\\\/\u007f\u2028"');
});

test("non-object tools have no digest; deep nesting gives no digest instead of a crash", () => {
  assert.equal(toolDigest([]), null);
  assert.equal(toolDigest("x"), null);
  assert.equal(toolDigest(null), null);
  let deep = "1";
  for (let i = 0; i < 5000; i++) deep = `[${deep}]`;
  assert.equal(toolDigest(parse(`{"name":"t","x":${deep}}`)), null);
});

test("toolSetDigest is order independent and null when any tool has no digest", () => {
  const a = parse('{"name":"a","description":"1"}');
  const b = parse('{"name":"b","description":"2"}');
  const s1 = toolSetDigest([a, b]);
  const s2 = toolSetDigest([b, a]);
  assert.ok(s1);
  assert.equal(s1, s2);
  assert.equal(toolSetDigest([a, parse('{"name":"c","x":1e300}')]), null);
});
