#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$ROOT/env.sh"

python3 -m unittest discover -s "$ROOT/tests" -q
pytest -q "$ROOT"/tests/test_final_benchmark_*.py
python3 -m py_compile "$ROOT"/ico_*.py "$ROOT"/tests/*.py "$ROOT"/scripts/run_corpus_matrix.py "$ROOT"/scripts/benchmark_ico_solve.py

for tool in binwalk pngcheck qpdf 7zz zsteg stegseek steghide exiftool foremost \
  ffuf feroxbuster gobuster hashcat hydra john nmap r2 sqlmap yara tshark vol gdb jq ffmpeg \
  qiling scalpel strace ltrace; do
  command -v "$tool" >/dev/null || { echo "MISSING: $tool" >&2; exit 1; }
done

./ico-scan --help >/dev/null
./ico-solve --help >/dev/null
qiling --probe >/dev/null
scalpel --help >/dev/null
strace --help >/dev/null
ltrace --help >/dev/null
tool_count=$(./ico-solve --tools | wc -l | tr -d ' ')
expected_tool_count=$(python3 - <<'PY'
from ico_tool_adapters import TOOL_SPECS
print(len(TOOL_SPECS))
PY
)
[ "$tool_count" -eq "$expected_tool_count" ] || { echo "ico-solve tool inventory mismatch: $tool_count/$expected_tool_count" >&2; exit 1; }

fixture_dir=$(mktemp -d /tmp/ico-scan-verify.XXXXXX)
python tests/fixtures/make_fixtures.py --out "$fixture_dir/fixtures"
./ico-scan \
  "$fixture_dir/fixtures/direct.bin" \
  "$fixture_dir/fixtures/fixture.zip" \
  "$fixture_dir/fixtures/negative.txt" \
  --out "$fixture_dir/report" --max-depth 2 --max-files 20 --max-bytes 1048576 --timeout 5 >/tmp/ico-scan-verify.log
python - "$fixture_dir/report/report.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
values = {item["value"] for item in report["candidates"]}
assert values == {"ico{fixture_direct}", "CTF{fixture_nested}"}, values
assert all(item["state"] == "candidate" for item in report["candidates"])
print("ico-scan fixture smoke: OK")
PY

ico_solve_flag=$(./ico-solve "$fixture_dir/fixtures/direct.bin" --mode fast)
[ "$ico_solve_flag" = "ico{fixture_direct}" ] || { echo "ico-solve fixture smoke failed: $ico_solve_flag" >&2; exit 1; }
echo "ico-solve fixture smoke: OK"

benchmark_json=$(python3 "$ROOT/scripts/benchmark_ico_solve.py" "$fixture_dir/fixtures/direct.bin" --mode fast --repeat 2)
python3 - "$benchmark_json" <<'PY'
import json
import sys

report = json.loads(sys.argv[1])
assert len(report["runs"]) == 2, report
assert report["runs"][0]["selected_flags"] >= 1, report
assert report["runs"][1]["adapter_cache_hits"] >= 1, report
print("ico-solve benchmark smoke: OK")
PY

final_benchmark_dir=$(mktemp -d /tmp/ico-final-benchmark-verify.XXXXXX)
python3 "$ROOT/scripts/generate_final_benchmark.py" \
  --round 1 --root "$final_benchmark_dir/corpus" --manifest "$final_benchmark_dir/expected.json" >/dev/null
./ico-solve "$final_benchmark_dir/corpus" --mode fast --workers 2 --deadline 120 --debug "$final_benchmark_dir/run" >/dev/null
python3 "$ROOT/scripts/score_final_benchmark.py" \
  --report "$final_benchmark_dir/run/report.json" \
  --manifest "$final_benchmark_dir/expected.json" \
  --corpus "$final_benchmark_dir/corpus" \
  --out "$final_benchmark_dir/scorecard.json" >/tmp/ico-final-benchmark-score.log
python3 - "$final_benchmark_dir/scorecard.json" <<'PY'
import json
import sys

score = json.load(open(sys.argv[1], encoding="utf-8"))
assert score["verified_count"] == 50, score
assert score["false_positive_count"] == 0, score
assert score["ten_out_of_ten"] is True, score
print("ico final-50 benchmark smoke: OK")
PY

hard_benchmark_dir=$(mktemp -d /tmp/ico-hardest-benchmark-verify.XXXXXX)
python3 "$ROOT/scripts/generate_final_benchmark.py" \
  --round 1 --profile hardest --root "$hard_benchmark_dir/corpus" --manifest "$hard_benchmark_dir/expected.json" >/dev/null
./ico-solve "$hard_benchmark_dir/corpus" --mode fast --workers 2 --deadline 120 --debug "$hard_benchmark_dir/run" >/dev/null
python3 "$ROOT/scripts/score_final_benchmark.py" \
  --report "$hard_benchmark_dir/run/report.json" \
  --manifest "$hard_benchmark_dir/expected.json" \
  --corpus "$hard_benchmark_dir/corpus" \
  --out "$hard_benchmark_dir/scorecard.json" >/tmp/ico-hardest-benchmark-score.log
python3 - "$hard_benchmark_dir/scorecard.json" <<'PY'
import json
import sys

score = json.load(open(sys.argv[1], encoding="utf-8"))
assert score["profile"] == "hardest", score
assert score["verified_count"] == 50, score
assert score["false_positive_count"] == 0, score
assert score["ten_out_of_ten"] is True, score
print("ico hardest-50 benchmark smoke: OK")
PY

[ -f "$ROOT/CyberChef/app/CyberChef_v11.5.0.html" ]
[ -x "$ROOT/steghide/bin/steghide" ]
[ -x "$ROOT/stegseek" ]

python - <<'PY'
import angr, pwn, Crypto, sympy
print("Python CTF stack: OK")
PY
rsactftool --help >/dev/null
vol -h >/dev/null

if [ -n "${ICO_CTF_REAL_ROOT:-}" ]; then
  task_report=$(mktemp -d /tmp/ico-scan-task-pack.XXXXXX)
  ./ico-scan "$ICO_CTF_REAL_ROOT" --out "$task_report/report" >/tmp/ico-scan-task-pack.log
  python - "$task_report/report/report.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
assert report["summary"]["solved_tasks"] == 10, report["summary"]
assert report["summary"]["task_failure_count"] == 0, report["summary"]
assert sum(item["state"] == "hash-verified" for item in report["candidates"]) == 10
print("ico-scan task-pack smoke: OK")
PY
fi

if [ -n "${ICO_QUALS_ROOT:-}" ]; then
  quals_report=$(mktemp -d /tmp/ico-scan-quals-pack.XXXXXX)
  ./ico-scan "$ICO_QUALS_ROOT" --out "$quals_report/report" >/tmp/ico-scan-quals-pack.log
  python - "$quals_report/report/report.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
summary = report["summary"]
assert summary["quals_task_count"] == 10, summary
assert summary["quals_candidate_task_count"] >= 2, summary
assert summary["quals_payload_ready_count"] == 2, summary
assert summary["task_failure_count"] == 0, summary
print("ico-scan real-quals smoke: OK")
PY
fi

matrix_inputs=""
if [ -n "${ICO_CTF_STARTER_ROOT:-}" ]; then matrix_inputs="$matrix_inputs $ICO_CTF_STARTER_ROOT"; fi
if [ -n "${ICO_CTF_REAL_ROOT:-}" ]; then matrix_inputs="$matrix_inputs $ICO_CTF_REAL_ROOT"; fi
if [ -n "${ICO_QUALS_ROOT:-}" ]; then matrix_inputs="$matrix_inputs $ICO_QUALS_ROOT"; fi
if [ -n "$matrix_inputs" ]; then
  matrix_report=$(mktemp -d /tmp/ico-scan-corpus-matrix.XXXXXX)
  # shellcheck disable=SC2086
  python3 "$ROOT/scripts/run_corpus_matrix.py" $matrix_inputs --out "$matrix_report"
fi

echo "Binary stack: OK"
echo "Toolkit: $ROOT"
