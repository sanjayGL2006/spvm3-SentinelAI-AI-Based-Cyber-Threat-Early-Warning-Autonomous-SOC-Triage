import os
import sys
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PYTHON = sys.executable

def run(title, cmd, cwd=None):
    print(f"\n{'=' * 20} {title} {'=' * 20}")
    res = subprocess.run(cmd, cwd=cwd or ROOT, text=True, capture_output=True)
    if res.stdout:
        print(res.stdout.strip())
    if res.stderr:
        print(res.stderr.strip())
    if res.returncode != 0:
        print(f"FAILED with code {res.returncode}")
        return False
    print("STATUS: SUCCESS")
    return True

all_ok = True

# 1. Ruff lint
venv_ruff = ROOT / "backend" / "venv" / "Scripts" / "ruff.exe"
if venv_ruff.exists():
    all_ok &= run("1. RUFF LINT", [str(venv_ruff), "check", "backend/", "--select", "E9,F"])
else:
    print("Ruff not found in venv")

# 2. Model gate check
model_gate_code = (
    "import sys; sys.path.append('backend'); "
    "from detector import _load_xgb; "
    "clf = _load_xgb(); "
    "assert clf is not None, 'Model failed to load!'; "
    "print('Model gate passed:', type(clf).__name__)"
)
all_ok &= run("2. MODEL GATE CHECK", [PYTHON, "-c", model_gate_code])

# 3. Pytest suite
all_ok &= run("3. BACKEND PYTEST SUITE", [PYTHON, "-m", "pytest", "backend/tests", "-v"])

# 4. Standalone HTML check
html_gate_code = (
    "import os; "
    "s = os.path.getsize('sentinelai_dashboard.html'); "
    "assert s > 20000, 'HTML too small'; "
    "print(f'Dashboard HTML verified: {s} bytes')"
)
all_ok &= run("4. DASHBOARD HTML CHECK", [PYTHON, "-c", html_gate_code])

# 5. Frontend Build
npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
all_ok &= run("5. FRONTEND PRODUCTION BUILD", [npm_cmd, "run", "build"], cwd=ROOT / "frontend")

print("\n" + "=" * 55)
print("OVERALL VERIFICATION:", "ALL PASSED (100%)" if all_ok else "FAILURES ENCOUNTERED")
print("=" * 55)
