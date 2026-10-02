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

# Every compiled test runs except the files named here. A new test file is
# picked up without editing this script.
SKIP="crossLangParity driftTelemetry holdMessage"

for name in $SKIP; do
  if [ ! -f "test/$name.test.ts" ]; then
    echo "missing skipped file: test/$name.test.ts" >&2
    exit 1
  fi
done

rm -rf dist/test
npm run build

run=()
while IFS= read -r js; do
  name=$(basename "$js" .test.js)
  case " $SKIP " in
    *" $name "*) continue ;;
  esac
  run+=("$js")
done < <(find dist/test -name '*.test.js' | sort)

if [ "${#run[@]}" -eq 0 ]; then
  echo "no test files found under dist/test" >&2
  exit 1
fi
echo "RUN ${#run[@]} files: ${run[*]}"
node --test "${run[@]}"
