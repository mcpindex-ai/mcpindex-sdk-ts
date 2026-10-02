/**
 * Cross-language PARITY: the TS action classifier must reproduce the Python
 * `cse.action_class.classify` output byte-for-byte. The `expected` blocks below are
 * GOLDEN values captured by running the live Python classifier (corpus_eval) on the
 * same inputs. Regenerate via tools that dump `classify(...).model_dump(mode="json")`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { classify, classifyToolDef } from "../src/actionClass.js";
import { Gate, Posture } from "../src/gate.js";
import { PreflightPin, Decision } from "../src/preflight.js";
import type { ToolDef } from "../src/preflight.js";

const CASES = [
  {
    "name": "read_file",
    "description": "Reads a file from disk and returns its contents.",
    "inputSchema": {
      "properties": {
        "path": {
          "type": "string"
        }
      }
    },
    "annotations": null,
    "expected": {
      "action_types": [
        "read"
      ],
      "effective_action_type": "read",
      "resource": {
        "kind": "data",
        "pattern": "single-arg",
        "scope_hint": "narrow"
      },
      "side_effect_class": "none",
      "reversibility": "reversible",
      "egress": "none",
      "autonomy_ceiling": "discovery",
      "autonomy_ceiling_basis": "static",
      "known_risk_notes": [],
      "evidence": [
        {
          "ref_type": "schema_flag",
          "ref_id": "domain.data"
        },
        {
          "ref_type": "schema_flag",
          "ref_id": "action.read"
        }
      ]
    }
  },
  {
    "name": "delete_repo",
    "description": "Permanently deletes a repository.",
    "inputSchema": {
      "properties": {
        "repo": {
          "type": "string"
        }
      }
    },
    "annotations": null,
    "expected": {
      "action_types": [
        "delete"
      ],
      "effective_action_type": "delete",
      "resource": {
        "kind": "unknown",
        "pattern": "single-arg",
        "scope_hint": "narrow"
      },
      "side_effect_class": "destructive",
      "reversibility": "irreversible",
      "egress": "internal",
      "autonomy_ceiling": "needs-approval",
      "autonomy_ceiling_basis": "static",
      "known_risk_notes": [
        {
          "note_class": "destructive_no_undo_path",
          "severity": "medium",
          "source": {
            "ref_type": "schema_flag",
            "ref_id": "action.delete"
          },
          "provenance": "derived"
        }
      ],
      "evidence": [
        {
          "ref_type": "schema_flag",
          "ref_id": "name_writeish"
        },
        {
          "ref_type": "schema_flag",
          "ref_id": "action.delete"
        }
      ]
    }
  },
  {
    "name": "create_issue",
    "description": "Creates a new issue in the tracker.",
    "inputSchema": {
      "properties": {
        "title": {
          "type": "string"
        },
        "body": {
          "type": "string"
        }
      }
    },
    "annotations": null,
    "expected": {
      "action_types": [
        "auth",
        "write"
      ],
      "effective_action_type": "auth",
      "resource": {
        "kind": "unknown",
        "pattern": "single-arg",
        "scope_hint": "narrow"
      },
      "side_effect_class": "local-write",
      "reversibility": "irreversible",
      "egress": "internal",
      "autonomy_ceiling": "needs-approval",
      "autonomy_ceiling_basis": "static",
      "known_risk_notes": [],
      "evidence": [
        {
          "ref_type": "schema_flag",
          "ref_id": "name_writeish"
        },
        {
          "ref_type": "schema_flag",
          "ref_id": "write_payload_param"
        },
        {
          "ref_type": "schema_flag",
          "ref_id": "action.auth"
        }
      ]
    }
  },
  {
    "name": "send_email",
    "description": "Sends an email to a recipient.",
    "inputSchema": {
      "properties": {
        "to": {
          "type": "string"
        },
        "subject": {
          "type": "string"
        }
      }
    },
    "annotations": null,
    "expected": {
      "action_types": [
        "send"
      ],
      "effective_action_type": "send",
      "resource": {
        "kind": "comms",
        "pattern": "single-arg",
        "scope_hint": "narrow"
      },
      "side_effect_class": "outbound",
      "reversibility": "hard-to-reverse",
      "egress": "external",
      "autonomy_ceiling": "needs-approval",
      "autonomy_ceiling_basis": "static",
      "known_risk_notes": [],
      "evidence": [
        {
          "ref_type": "schema_flag",
          "ref_id": "name_writeish"
        },
        {
          "ref_type": "schema_flag",
          "ref_id": "write_payload_param"
        },
        {
          "ref_type": "schema_flag",
          "ref_id": "domain.comms"
        },
        {
          "ref_type": "schema_flag",
          "ref_id": "action.send"
        }
      ]
    }
  },
  {
    "name": "charge_card",
    "description": "Charges a customer's credit card.",
    "inputSchema": {
      "properties": {
        "amount": {
          "type": "number"
        },
        "token": {
          "type": "string"
        }
      }
    },
    "annotations": null,
    "expected": {
      "action_types": [
        "unknown"
      ],
      "effective_action_type": "unknown",
      "resource": {
        "kind": "payments",
        "pattern": "single-arg",
        "scope_hint": "narrow"
      },
      "side_effect_class": "destructive",
      "reversibility": "irreversible",
      "egress": "internal",
      "autonomy_ceiling": "never-unattended",
      "autonomy_ceiling_basis": "static",
      "known_risk_notes": [
        {
          "note_class": "destructive_no_undo_path",
          "severity": "medium",
          "source": {
            "ref_type": "schema_flag",
            "ref_id": "action.unknown"
          },
          "provenance": "derived"
        }
      ],
      "evidence": [
        {
          "ref_type": "schema_flag",
          "ref_id": "name_writeish"
        },
        {
          "ref_type": "schema_flag",
          "ref_id": "write_payload_param"
        },
        {
          "ref_type": "schema_flag",
          "ref_id": "requires_credential"
        },
        {
          "ref_type": "schema_flag",
          "ref_id": "domain.payments"
        },
        {
          "ref_type": "schema_flag",
          "ref_id": "action.unknown"
        }
      ]
    }
  },
  {
    "name": "frobnicate",
    "description": "Does a thing.",
    "inputSchema": {
      "properties": {
        "x": {
          "type": "string"
        }
      }
    },
    "annotations": null,
    "expected": {
      "action_types": [
        "unknown"
      ],
      "effective_action_type": "unknown",
      "resource": {
        "kind": "unknown",
        "pattern": "single-arg",
        "scope_hint": "narrow"
      },
      "side_effect_class": "local-write",
      "reversibility": "reversible",
      "egress": "internal",
      "autonomy_ceiling": "never-unattended",
      "autonomy_ceiling_basis": "static",
      "known_risk_notes": [],
      "evidence": [
        {
          "ref_type": "schema_flag",
          "ref_id": "action.unknown"
        }
      ]
    }
  },
  {
    "name": "cleanup_workspace",
    "description": "Tidies the workspace.",
    "inputSchema": {
      "properties": {
        "scope": {
          "type": "string"
        }
      }
    },
    "annotations": {
      "destructiveHint": true
    },
    "expected": {
      "action_types": [
        "delete"
      ],
      "effective_action_type": "delete",
      "resource": {
        "kind": "unknown",
        "pattern": "single-arg",
        "scope_hint": "narrow"
      },
      "side_effect_class": "destructive",
      "reversibility": "irreversible",
      "egress": "internal",
      "autonomy_ceiling": "needs-approval",
      "autonomy_ceiling_basis": "static",
      "known_risk_notes": [
        {
          "note_class": "destructive_no_undo_path",
          "severity": "medium",
          "source": {
            "ref_type": "schema_flag",
            "ref_id": "action.delete"
          },
          "provenance": "derived"
        }
      ],
      "evidence": [
        {
          "ref_type": "schema_flag",
          "ref_id": "action.delete"
        }
      ]
    }
  },
  {
    "name": "delete_thing",
    "description": "Removes a thing.",
    "inputSchema": {
      "properties": {
        "id": {
          "type": "string"
        }
      }
    },
    "annotations": {
      "readOnlyHint": true
    },
    "expected": {
      "action_types": [
        "delete"
      ],
      "effective_action_type": "delete",
      "resource": {
        "kind": "unknown",
        "pattern": "single-arg",
        "scope_hint": "narrow"
      },
      "side_effect_class": "destructive",
      "reversibility": "irreversible",
      "egress": "internal",
      "autonomy_ceiling": "needs-approval",
      "autonomy_ceiling_basis": "static",
      "known_risk_notes": [
        {
          "note_class": "annotation_contradicts_probe",
          "severity": "high",
          "source": {
            "ref_type": "schema_flag",
            "ref_id": "readonly_hint_vs_writeish"
          },
          "provenance": "derived"
        },
        {
          "note_class": "destructive_no_undo_path",
          "severity": "medium",
          "source": {
            "ref_type": "schema_flag",
            "ref_id": "action.delete"
          },
          "provenance": "derived"
        }
      ],
      "evidence": [
        {
          "ref_type": "schema_flag",
          "ref_id": "name_writeish"
        },
        {
          "ref_type": "schema_flag",
          "ref_id": "action.delete"
        }
      ]
    }
  },
  {
    "name": "search_docs",
    "description": "Search the docs by glob.",
    "inputSchema": {
      "properties": {
        "glob": {
          "type": "string"
        }
      }
    },
    "annotations": null,
    "expected": {
      "action_types": [
        "search"
      ],
      "effective_action_type": "search",
      "resource": {
        "kind": "data",
        "pattern": "glob",
        "scope_hint": "unbounded"
      },
      "side_effect_class": "none",
      "reversibility": "reversible",
      "egress": "none",
      "autonomy_ceiling": "discovery",
      "autonomy_ceiling_basis": "static",
      "known_risk_notes": [],
      "evidence": [
        {
          "ref_type": "schema_flag",
          "ref_id": "domain.data"
        },
        {
          "ref_type": "schema_flag",
          "ref_id": "action.search"
        }
      ]
    }
  },
  {
    "name": "update_records",
    "description": "Update many records.",
    "inputSchema": {
      "properties": {
        "ids": {
          "type": "array"
        }
      }
    },
    "annotations": null,
    "expected": {
      "action_types": [
        "update"
      ],
      "effective_action_type": "update",
      "resource": {
        "kind": "data",
        "pattern": "wildcard",
        "scope_hint": "unbounded"
      },
      "side_effect_class": "local-write",
      "reversibility": "hard-to-reverse",
      "egress": "internal",
      "autonomy_ceiling": "reversible",
      "autonomy_ceiling_basis": "static",
      "known_risk_notes": [],
      "evidence": [
        {
          "ref_type": "schema_flag",
          "ref_id": "name_writeish"
        },
        {
          "ref_type": "schema_flag",
          "ref_id": "domain.data"
        },
        {
          "ref_type": "schema_flag",
          "ref_id": "action.update"
        }
      ]
    }
  },
  {
    "name": "list_items",
    "description": "Lists items.",
    "inputSchema": {
      "properties": {}
    },
    "annotations": null,
    "expected": {
      "action_types": [
        "list"
      ],
      "effective_action_type": "list",
      "resource": {
        "kind": "data",
        "pattern": "literal",
        "scope_hint": "narrow"
      },
      "side_effect_class": "none",
      "reversibility": "reversible",
      "egress": "none",
      "autonomy_ceiling": "discovery",
      "autonomy_ceiling_basis": "static",
      "known_risk_notes": [],
      "evidence": [
        {
          "ref_type": "schema_flag",
          "ref_id": "domain.data"
        },
        {
          "ref_type": "schema_flag",
          "ref_id": "action.list"
        }
      ]
    }
  },
  {
    "name": "run_script",
    "description": "Runs an arbitrary script.",
    "inputSchema": {
      "properties": {
        "cmd": {
          "type": "string"
        }
      }
    },
    "annotations": null,
    "expected": {
      "action_types": [
        "execute"
      ],
      "effective_action_type": "execute",
      "resource": {
        "kind": "unknown",
        "pattern": "single-arg",
        "scope_hint": "narrow"
      },
      "side_effect_class": "destructive",
      "reversibility": "irreversible",
      "egress": "internal",
      "autonomy_ceiling": "never-unattended",
      "autonomy_ceiling_basis": "static",
      "known_risk_notes": [
        {
          "note_class": "destructive_no_undo_path",
          "severity": "medium",
          "source": {
            "ref_type": "schema_flag",
            "ref_id": "action.execute"
          },
          "provenance": "derived"
        }
      ],
      "evidence": [
        {
          "ref_type": "schema_flag",
          "ref_id": "name_writeish"
        },
        {
          "ref_type": "schema_flag",
          "ref_id": "write_payload_param"
        },
        {
          "ref_type": "schema_flag",
          "ref_id": "action.execute"
        }
      ]
    }
  }
] as const;

for (const c of CASES) {
  test(`actionClass parity: ${c.name}`, () => {
    const got = classify(c.name, c.description, c.inputSchema, c.annotations ?? null);
    assert.deepStrictEqual(JSON.parse(JSON.stringify(got)), c.expected);
  });
}

const READ_TOOL: ToolDef = {
  name: "read_file",
  description: "Reads a file.",
  inputSchema: { properties: { path: { type: "string" } } },
};

test("gate wiring: evaluate() attaches the advisory classification (default-on)", () => {
  const gate = new Gate({ pin: new PreflightPin(), serverId: "srv" });
  gate.observe("read_file", READ_TOOL);
  const v = gate.evaluate("read_file", READ_TOOL);
  assert.equal(v.decision, Decision.PROCEED);
  assert.ok(v.actionClassification, "classification present on the static verdict");
  assert.equal(v.actionClassification?.effective_action_type, "read");
});

test("gate wiring: the EFFECTIVE verdict keeps the grade through notify-only", () => {
  const gate = new Gate({ pin: new PreflightPin(), serverId: "srv", posture: Posture.MONITOR });
  gate.observe("read_file", READ_TOOL);
  const drifted: ToolDef = {
    name: "read_file",
    description: "Reads a file.",
    inputSchema: { properties: { path: { type: "string" }, owner: { type: "string" } }, required: ["owner"] },
  };
  const [stat, eff] = gate.decide("read_file", drifted);
  assert.equal(stat.decision, Decision.HOLD);
  assert.equal(eff.decision, Decision.PROCEED,
      "MONITOR notifies and proceeds on a drift; tamper evidence still stops the call");
  assert.ok(eff.actionClassification, "effective verdict keeps the advisory grade through notify-only");
});

test("wrapper: missing inputSchema is coerced to {} (Python parity)", () => {
  const viaWrapper = classifyToolDef("read_file", { description: "Reads a file." } as unknown as ToolDef);
  const direct = classify("read_file", "Reads a file.", {});
  assert.deepStrictEqual(viaWrapper, direct);
  assert.equal(viaWrapper?.resource.pattern, "literal");
  assert.equal(viaWrapper?.resource.scope_hint, "narrow");
});

test("wrapper: a non-string description is stringified, not dropped (no fail-open)", () => {
  const obj = { note: "charge the customer credit card" };
  const schema = { properties: { id: { type: "string" } } };
  const viaWrapper = classifyToolDef("lookup", { description: obj, inputSchema: schema } as unknown as ToolDef);
  // content reaches the classifier (not silently zeroed to "")
  assert.deepStrictEqual(viaWrapper, classify("lookup", JSON.stringify(obj), schema));
  // and it is NOT the suppressed empty-description classification
  assert.notDeepStrictEqual(viaWrapper, classify("lookup", "", schema));
});

test("opt-out: MCPINDEX_ACTION_CLASSIFICATION_ENABLED=0 yields a null block", () => {
  const prev = process.env.MCPINDEX_ACTION_CLASSIFICATION_ENABLED;
  process.env.MCPINDEX_ACTION_CLASSIFICATION_ENABLED = "0";
  try {
    const gate = new Gate({ pin: new PreflightPin(), serverId: "srv" });
    gate.observe("read_file", READ_TOOL);
    assert.equal(gate.evaluate("read_file", READ_TOOL).actionClassification, null);
  } finally {
    if (prev === undefined) delete process.env.MCPINDEX_ACTION_CLASSIFICATION_ENABLED;
    else process.env.MCPINDEX_ACTION_CLASSIFICATION_ENABLED = prev;
  }
});
