#!/bin/bash
# setenv.py reads its configuration from the INPUT_* variables and writes
# GITHUB_ENV / GITHUB_OUTPUT itself. Its stdout is never evaluated.
set -euo pipefail
exec python3 "$(dirname "$0")/setenv.py"
