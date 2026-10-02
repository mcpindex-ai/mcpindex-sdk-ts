#!/usr/bin/env bash
# Public CI and the npm release job run this. `npm test` stays the full suite
# and fails closed when the private Python tree is absent. That is correct,
# and it is what mcpindex-trust runs. Here we name the files we do not run.
set -eu
cd "$(dirname "$0")/.."

echo "SKIP test/crossLangParity.test.ts"
echo "  Three tests import live Python (trust.result_scan, trust.schema_scan, tooling.cse.schema_diff) via uv."
echo "  This repo has no such tree: ModuleNotFoundError. They run in mcpindex-trust."
echo "SKIP test/driftTelemetry.test.ts"
echo "  Two tests run uv with cwd at corpus_eval, four directories above the compiled test, to import tooling.cse.drift_telemetry."
echo "  That directory is not here, so uv is never started (ENOENT). They run in mcpindex-trust."
echo "SKIP test/holdMessage.test.ts"
echo "  One test reads corpus_eval/tooling/cse/gate.py two directories above this repo and compares 16 constants."
echo "  That file is not here (ENOENT). The rest of the file runs with it, in mcpindex-trust."
echo "NOTE test/descriptionNumeric.test.ts runs here. Its corpus fixture parity_sample.json is absent, and that one test prints SKIP parity and returns. The behaviour table still runs."
echo "NOTE test/parity.test.ts runs here. It compares pinned hash constants. It does not execute Python."

for f in \
  test/crossLangParity.test.ts \
  test/driftTelemetry.test.ts \
  test/holdMessage.test.ts
do
  if [ ! -f "$f" ]; then
    echo "missing skipped file: $f" >&2
    exit 1
  fi
done

npm run build
node --test \
  dist/test/actionClass.test.js \
  dist/test/ambient.test.js \
  dist/test/descriptionNumeric.test.js \
  dist/test/driftQuery.test.js \
  dist/test/integration.test.js \
  dist/test/login.test.js \
  dist/test/parity.test.js \
  dist/test/resultScan.test.js
