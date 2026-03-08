#!/usr/bin/env bash
# check.sh — полная проверка файла или директории
# Использование: ./check.sh src/security/crypto/core/exceptions.py
#          или: ./check.sh src/security/

set -euo pipefail

TARGET="${1:-.}"
PASS=0
FAIL=0
ERRORS=()

GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
BOLD="\033[1m"
RESET="\033[0m"

run_check() {
    local name="$1"
    shift
    echo -e "${CYAN}${BOLD}[$name]${RESET} $*"
    if "$@"; then
        echo -e "${GREEN}✓ $name passed${RESET}\n"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}✗ $name failed${RESET}\n"
        FAIL=$((FAIL + 1))
        ERRORS+=("$name")
    fi
}

echo -e "${BOLD}========================================${RESET}"
echo -e "${BOLD} Checking: ${CYAN}$TARGET${RESET}"
echo -e "${BOLD}========================================${RESET}\n"

run_check "TOML"         python3 -c "import tomllib; tomllib.load(open('pyproject.toml', 'rb')); print('OK')"
run_check "ruff lint"    ruff check "$TARGET"
run_check "ruff format"  ruff format --check "$TARGET"
run_check "mypy"         mypy --strict "$TARGET"
run_check "basedpyright" basedpyright "$TARGET"
run_check "bandit"       bandit -r "$TARGET" -ll

if [[ "$TARGET" == tests/* ]] || [[ "$TARGET" == *test_* ]]; then
    run_check "pytest" pytest "$TARGET" -v
else
    echo -e "${YELLOW}[pytest] skipped${RESET}\n"
fi

echo -e "${BOLD}========================================${RESET}"
echo -e "${BOLD} Results: ${GREEN}$PASS passed${RESET} / ${RED}$FAIL failed${RESET}"
[ ${#ERRORS[@]} -gt 0 ] && echo -e "${RED} Failed: ${ERRORS[*]}${RESET}"
echo -e "${BOLD}========================================${RESET}"

[ $FAIL -eq 0 ]
