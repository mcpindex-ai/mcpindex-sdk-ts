import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Gate, Posture } from "../src/gate.js";
import { Decision, PreflightPin, type ToolDef } from "../src/preflight.js";

const BASE: ToolDef = {
  name: "search",
  description: "search the index",
  inputSchema: {
    type: "object",
    properties: { q: { type: "string" } },
    required: ["q"],
  },
};

const TEXT: Record<string, unknown> = {
  description: "a note",
  title: "A note",
  enum: ["a", "b"],
  default: "a",
  examples: ["a"],
};

function added(field: string, value: unknown): ToolDef {
  return {
    ...BASE,
    inputSchema: {
      type: "object",
      properties: {
        q: { type: "string" },
        extra: { type: "string", [field]: value },
      },
      required: ["q"],
    },
  };
}

function existing(field: string, value: unknown): ToolDef {
  return {
    ...BASE,
    inputSchema: {
      type: "object",
      properties: { q: { type: "string", [field]: value } },
      required: ["q"],
    },
  };
}

function textFree(): ToolDef {
  return {
    ...BASE,
    inputSchema: {
      type: "object",
      properties: {
        q: { type: "string" },
        extra: { type: "integer", minimum: 0, maximum: 10 },
      },
      required: ["q"],
    },
  };
}

function fresh(posture: Posture): { gate: Gate; pin: PreflightPin } {
  const pin = new PreflightPin();
  const gate = new Gate({
    pin,
    serverId: "srv",
    posture,
    autoAcceptBenign: true,
  });
  gate.observe("search", BASE);
  return { gate, pin };
}

test("assess does not write the pin", () => {
  const pin = new PreflightPin();
  const gate = new Gate({
    pin,
    serverId: "srv",
    posture: Posture.GUARD,
    autoAcceptBenign: true,
  });
  gate.observe("search", BASE);
  const before = pin.get("srv", "search")?.definitionHash;
  let writes = 0;
  pin.put = () => {
    writes += 1;
    throw new Error("pin write");
  };
  const [staticVerdict, effective, effects] = gate.assess("search", textFree());
  assert.equal(writes, 0);
  assert.equal(pin.get("srv", "search")?.definitionHash, before);
  assert.equal(effective.decision, Decision.PROCEED);
  assert.deepEqual(
    effects.map((effect) => effect.kind),
    ["repin", "drift", "fleet"],
  );
  assert.equal(staticVerdict.toolName, "search");
});

test("decide equals assess plus commit across the vector file", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const rows = JSON.parse(
    readFileSync(join(here, "../../test/fixtures/contract-bytes.json"), "utf8"),
  ) as Array<{ input: Record<string, unknown> }>;
  const cases: ToolDef[] = [
    textFree(),
    added("description", "a note"),
    BASE,
    ...rows.map((row) => ({ ...BASE, inputSchema: row.input })),
  ];
  for (const observed of cases) {
    const left = fresh(Posture.GUARD);
    const right = fresh(Posture.GUARD);
    const decided = left.gate.decide("search", observed);
    const assessed = right.gate.assess("search", observed);
    const committed = right.gate.commit(assessed[0], assessed[2]);
    assert.equal(decided[0].decision, committed[0].decision);
    assert.equal(decided[0].reason, committed[0].reason);
    assert.equal(decided[1].decision, committed[1].decision);
    assert.equal(
      left.pin.get("srv", "search")?.definitionHash,
      right.pin.get("srv", "search")?.definitionHash,
    );
  }
});

test("schema text holds under Guard and Strict", () => {
  for (const posture of [Posture.GUARD, Posture.STRICT]) {
    for (const [field, value] of Object.entries(TEXT)) {
      for (const observed of [added(field, value), existing(field, value)]) {
        const effective = fresh(posture).gate.decide("search", observed)[1];
        assert.equal(effective.decision, Decision.HOLD, `${posture} ${field}`);
      }
    }
    const free = fresh(posture).gate.decide("search", textFree())[1];
    assert.equal(free.decision, Decision.PROCEED, String(posture));
  }
});

test("a 600-deep outputSchema holds under Guard", () => {
  const nest = (leaf: Record<string, unknown>): Record<string, unknown> => {
    let node = leaf;
    for (let i = 0; i < 600; i += 1) {
      node = { type: "object", properties: { n: node } };
    }
    return node;
  };
  const pin = new PreflightPin();
  const gate = new Gate({ pin, serverId: "srv", posture: Posture.GUARD });
  const base: ToolDef = { ...BASE, outputSchema: { type: "object" } };
  gate.observe("search", base);
  const stored = pin.get("srv", "search");
  assert.ok(stored?.schema);
  stored.schema.outputSchema = nest({ type: "string" });
  const live: ToolDef = {
    ...BASE,
    outputSchema: nest({ type: "integer" }),
  };
  const effective = gate.decide("search", live)[1];
  assert.equal(effective.decision, Decision.HOLD);
  assert.match(effective.reason, /could not complete/);
});
