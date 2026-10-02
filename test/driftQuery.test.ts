/**
 * Fleet drift-query (M3 SDK) tests. Pins: the opt-in gate (off => no query, no advisory), the
 * fail-OPEN contract (a throwing/unknown response never warns + never crashes the gate), the
 * cache semantics (drifted true => advisory; false => clean => no advisory), and the end-to-end
 * gate integration (observe prefetches → evaluate attaches `fleetAdvisory`, AD-6: PROCEED stays
 * PROCEED). The queried fp is the same salted fingerprint the emitter uses — no new exposure.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { driftQuery, type FleetTransport } from "../src/driftQuery.js";
import { driftTelemetry, type DriftSignal } from "../src/driftTelemetry.js";
import { Gate } from "../src/gate.js";
import { PreflightPin, Decision, renderVerdict, type ToolDef } from "../src/preflight.js";

const TOOL: ToolDef = {
  name: "do_thing",
  description: "d",
  inputSchema: { type: "object", properties: { a: { type: "string" } } },
};

async function withTelemetry(mode: string, fn: () => void | Promise<void>): Promise<void> {
  process.env.MCPINDEX_DRIFT_TELEMETRY = mode;
  driftTelemetry._reset();
  driftQuery._reset();
  try {
    await fn();
  } finally {
    delete process.env.MCPINDEX_DRIFT_TELEMETRY;
    driftTelemetry._reset();
    driftQuery._reset();
    driftQuery._setTransport((async () => null) as FleetTransport);
  }
}

test("opt-out: telemetry off => prefetch is a no-op, lookup returns null", () => {
  delete process.env.MCPINDEX_DRIFT_TELEMETRY;
  driftTelemetry._reset();
  driftQuery._reset();
  let called = false;
  driftQuery._setTransport((async () => {
    called = true;
    return { drifted: true, sources: 3, safety_relevant: true };
  }) as FleetTransport);
  driftQuery.prefetch("srv", "do_thing");
  assert.equal(called, false);
  assert.equal(driftQuery.lookup("srv", "do_thing"), null);
});

test("4-mode read/send gating matrix: prefetch vs enqueue", async () => {
  const matrix: Record<string, [boolean, boolean]> = {
    off: [false, false],
    lookup: [true, false],
    detection: [true, true],
    contribute: [true, true],
  };
  const saved = process.env.MCPINDEX_DRIFT_TELEMETRY;
  try {
    for (const [mode, [wantRead, wantSend]] of Object.entries(matrix)) {
      process.env.MCPINDEX_DRIFT_TELEMETRY = mode;
      driftTelemetry._reset();
      driftQuery._reset();
      let called = false;
      driftQuery._setTransport((async () => {
        called = true;
        return { drifted: false };
      }) as FleetTransport);
      driftQuery.prefetch("srv", "do_thing");
      await driftQuery._settle();
      assert.equal(called, wantRead, `${mode}: prefetch/read`);
      driftTelemetry.recordPin("srv", "do_thing", "h", "2026-06-09T05:00:00Z");
      assert.equal(driftTelemetry._drainForTest().length > 0, wantSend, `${mode}: send`);
    }
  } finally {
    if (saved === undefined) delete process.env.MCPINDEX_DRIFT_TELEMETRY;
    else process.env.MCPINDEX_DRIFT_TELEMETRY = saved;
    driftTelemetry._reset();
    driftQuery._reset();
    driftQuery._setTransport((async () => null) as FleetTransport);
  }
});

test("unknown mode fail-closed: no prefetch, no enqueue", async () => {
  const saved = process.env.MCPINDEX_DRIFT_TELEMETRY;
  process.env.MCPINDEX_DRIFT_TELEMETRY = "bogus";
  driftTelemetry._reset();
  driftQuery._reset();
  try {
    assert.equal(driftTelemetry.readEnabled(), false);
    assert.equal(driftTelemetry.sendEnabled(), false);
    let called = false;
    driftQuery._setTransport((async () => {
      called = true;
      return { drifted: false };
    }) as FleetTransport);
    driftQuery.prefetch("srv", "do_thing");
    await driftQuery._settle();
    assert.equal(called, false);
    driftTelemetry.recordPin("srv", "do_thing", "h", "2026-06-09T05:00:00Z");
    assert.equal(driftTelemetry._drainForTest().length, 0);
  } finally {
    if (saved === undefined) delete process.env.MCPINDEX_DRIFT_TELEMETRY;
    else process.env.MCPINDEX_DRIFT_TELEMETRY = saved;
    driftTelemetry._reset();
    driftQuery._reset();
    driftQuery._setTransport((async () => null) as FleetTransport);
  }
});

test("lookup mode: fleet query works, zero telemetry send on drift", async () => {
  await withTelemetry("lookup", async () => {
    const captured: DriftSignal[] = [];
    driftTelemetry._setTransport(async (batch) => {
      captured.push(...batch);
    });
    driftQuery._setTransport((async () => ({ drifted: true, sources: 2, safety_relevant: true })) as FleetTransport);
    const gate = new Gate({ pin: new PreflightPin(), serverId: "srv" });
    gate.observe("do_thing", TOOL);
    await driftQuery._settle();
    const adv = driftQuery.lookup("srv", "do_thing");
    assert.deepEqual(adv, { drifted: true, provenance: "crawl", sources: 2, safetyRelevant: true });
    const drifted: ToolDef = {
      name: "do_thing",
      description: "d",
      inputSchema: {
        type: "object",
        properties: { a: { type: "string" }, b: { type: "number" } },
        required: ["b"],
      },
    };
    gate.evaluate("do_thing", drifted);
    await driftTelemetry.flush();
    assert.equal(captured.length, 0);
  });
});

test("corroborated drift => advisory cached + returned", async () => {
  await withTelemetry("detection", async () => {
    driftQuery._setTransport((async () => ({ drifted: true, sources: 4, safety_relevant: true })) as FleetTransport);
    driftQuery.prefetch("srv", "do_thing");
    await driftQuery._settle();
    const adv = driftQuery.lookup("srv", "do_thing");
    assert.deepEqual(adv, { drifted: true, provenance: "crawl", sources: 4, safetyRelevant: true });
  });
});

test("clean (drifted:false) => no advisory; unknown (null) => no advisory, retryable", async () => {
  await withTelemetry("detection", async () => {
    driftQuery._setTransport((async () => ({ drifted: false })) as FleetTransport);
    driftQuery.prefetch("srv", "clean_tool");
    await driftQuery._settle();
    assert.equal(driftQuery.lookup("srv", "clean_tool"), null);
  });
  await withTelemetry("detection", async () => {
    driftQuery._setTransport((async () => null) as FleetTransport); // unknown
    driftQuery.prefetch("srv", "unknown_tool");
    await driftQuery._settle();
    assert.equal(driftQuery.lookup("srv", "unknown_tool"), null);
  });
});

test("fail-open: a throwing transport never warns and never throws", async () => {
  await withTelemetry("detection", async () => {
    driftQuery._setTransport((async () => {
      throw new Error("network down");
    }) as FleetTransport);
    driftQuery.prefetch("srv", "do_thing"); // must not throw
    await driftQuery._settle();
    assert.equal(driftQuery.lookup("srv", "do_thing"), null);
  });
});

test("gate integration: observe prefetches, evaluate attaches fleetAdvisory; PROCEED stays PROCEED (AD-6)", async () => {
  await withTelemetry("detection", async () => {
    driftQuery._setTransport((async () => ({ drifted: true, sources: 2, safety_relevant: false })) as FleetTransport);
    const gate = new Gate({ pin: new PreflightPin(), serverId: "srv" });
    gate.observe("do_thing", TOOL); // pins + prefetches
    await driftQuery._settle();
    const verdict = gate.evaluate("do_thing", TOOL); // contract matches the pin => PROCEED
    assert.equal(verdict.decision, Decision.PROCEED); // advisory NEVER moves the decision
    assert.deepEqual(verdict.fleetAdvisory, {
      drifted: true,
      provenance: "crawl",
      sources: 2,
      safetyRelevant: false,
    });
    assert.ok(renderVerdict(verdict).includes("FLEET"), "render should surface the fleet advisory");
  });
});

test("provenance installs => cached advisory has provenance installs", async () => {
  await withTelemetry("detection", async () => {
    driftQuery._setTransport((async () => ({
      drifted: true,
      provenance: "installs",
      sources: 3,
      safety_relevant: true,
    })) as FleetTransport);
    driftQuery.prefetch("srv", "do_thing");
    await driftQuery._settle();
    const adv = driftQuery.lookup("srv", "do_thing");
    assert.deepEqual(adv, { drifted: true, provenance: "installs", sources: 3, safetyRelevant: true });
  });
});

test("provenance absent => defaults to crawl (backward-safe)", async () => {
  await withTelemetry("detection", async () => {
    driftQuery._setTransport((async () => ({ drifted: true, sources: 2 })) as FleetTransport);
    driftQuery.prefetch("srv", "do_thing");
    await driftQuery._settle();
    const adv = driftQuery.lookup("srv", "do_thing");
    assert.deepEqual(adv, { drifted: true, provenance: "crawl", sources: 2, safetyRelevant: false });
  });
});

test("provenance crawl explicit => cached advisory has provenance crawl", async () => {
  await withTelemetry("detection", async () => {
    driftQuery._setTransport((async () => ({
      drifted: true,
      provenance: "crawl",
      sources: 1,
      safety_relevant: false,
    })) as FleetTransport);
    driftQuery.prefetch("srv", "do_thing");
    await driftQuery._settle();
    const adv = driftQuery.lookup("srv", "do_thing");
    assert.deepEqual(adv, { drifted: true, provenance: "crawl", sources: 1, safetyRelevant: false });
  });
});

test("gate integration: no fleet drift => fleetAdvisory is null", async () => {
  await withTelemetry("detection", async () => {
    driftQuery._setTransport((async () => ({ drifted: false })) as FleetTransport);
    const gate = new Gate({ pin: new PreflightPin(), serverId: "srv" });
    gate.observe("do_thing", TOOL);
    await driftQuery._settle();
    const verdict = gate.evaluate("do_thing", TOOL);
    assert.equal(verdict.fleetAdvisory, null);
  });
});
