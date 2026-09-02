#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
INSTALL_DEPS=0

usage() {
  cat <<'EOF'
Usage: scripts/restore-clean-install.sh [--install-deps]

Prepare this checkout as a clean Sitina installation. Runtime history and
credentials are never restored from Git.
EOF
}

while (($#)); do
  case "$1" in
    --install-deps) INSTALL_DEPS=1 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [[ -n "${SITINA_PYTHON:-}" && -x "${SITINA_PYTHON}" ]]; then
  PYTHON_BIN="${SITINA_PYTHON}"
elif [[ -x "$HOME/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3" ]]; then
  PYTHON_BIN="$HOME/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3"
else
  PYTHON_BIN="$(command -v python3)"
fi

"$PYTHON_BIN" -c 'import sys; assert sys.version_info[:2] == (3, 12), "Sitina requires Python 3.12"'

if ((INSTALL_DEPS)); then
  "$PYTHON_BIN" -m pip install --require-hashes --only-binary=:all: \
    -r "$ROOT/requirements-bplus.lock"
fi

export SITINA_HOME="$ROOT"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT/core${PYTHONPATH:+:$PYTHONPATH}"

"$PYTHON_BIN" - <<'PY'
from sitina.constants import SITINA_HOME
from sitina.install_identity import canonical_journal_native_home
from sitina.legacy.retirement import LegacyRuntimePolicy

active = canonical_journal_native_home()
configured = SITINA_HOME.expanduser().resolve(strict=False)
if configured != active:
    raise RuntimeError(f"restore requires the active Sitina installation: {configured} != {active}")
policy = LegacyRuntimePolicy.load(active)
if not policy.protected_environment:
    raise RuntimeError("restore requires protected=true for the active Sitina installation")
if not policy.fully_disabled:
    raise RuntimeError("restore requires Legacy fully disabled for the active Sitina installation")
if not policy.missing_legacy_is_valid:
    raise RuntimeError("restore requires missing Legacy to be valid for the active Sitina installation")
errors = policy.validate_protected()
if errors:
    raise RuntimeError("invalid active Sitina installation Legacy policy: " + "; ".join(errors))
print(f"validated active Sitina installation: {active}")
PY

chmod 755 "$ROOT/bin/sitina"
install -d -m 700 \
  "$ROOT/profiles" \
  "$ROOT/state/locks" \
  "$ROOT/state/code-mode" \
  "$ROOT/journal" \
  "$ROOT/cas" \
  "$ROOT/projections" \
  "$ROOT/output"

"$ROOT/bin/sitina" --help >/dev/null

printf 'Sitina clean checkout is ready at %s\n' "$ROOT"
printf 'Create profiles/<name>.env from profiles/default.env.template and keep raw tokens in Keychain.\n'
