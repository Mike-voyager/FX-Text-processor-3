#!/usr/bin/env bash
# check.sh — полная проверка файла или директории
# Использование: ./check.sh src/security/crypto/core/exceptions.py
#          или: ./check.sh src/security/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
        echo -e "${GREEN}✓ $name passed${RESET}"
        echo
        PASS=$((PASS + 1))
    else
        echo -e "${RED}✗ $name failed${RESET}"
        echo
        FAIL=$((FAIL + 1))
        ERRORS+=("$name")
    fi
}

echo -e "${BOLD}========================================${RESET}"
echo -e "${BOLD} Checking: ${CYAN}$TARGET${RESET}"
echo -e "${BOLD}========================================${RESET}"
echo

# --- TOML / конфиг проекта ---

run_check "TOML" python3 -c \
    "import tomllib, pathlib; tomllib.load(open(str(pathlib.Path('$SCRIPT_DIR')/'pyproject.toml'), 'rb')); print('OK')"

# --- Проверка наличия ключевых инструментов ---

for tool in ruff mypy bandit; do
    if ! command -v "$tool" &>/dev/null; then
        echo -e "${RED}[ERROR] $tool not found in PATH${RESET}"
        echo
        FAIL=$((FAIL + 1))
        ERRORS+=("$tool (not found)")
    fi
done

# Если критические тулзы отсутствуют — не продолжаем дальше
if (( FAIL > 0 )) && printf '%s\n' "${ERRORS[@]}" | grep -q '(not found)'; then
    echo -e "${BOLD}========================================${RESET}"
    echo -e "${RED} Missing required tools, aborting checks${RESET}"
    echo -e "${BOLD}========================================${RESET}"
    exit 1
fi

# --- Статический анализ и типы ---

run_check "ruff lint"   ruff check "$TARGET"
run_check "ruff format" ruff format --check "$TARGET"
run_check "mypy"        mypy --strict "$TARGET"

if command -v basedpyright &>/dev/null; then
    run_check "basedpyright" basedpyright "$TARGET"
else
    echo -e "${YELLOW}[basedpyright] not found, skipped${RESET}"
    echo
fi

run_check "bandit" bandit -r -ll "$TARGET"

# --- Тесты pytest ---

if [[ "$TARGET" == tests/* ]] || \
   [[ "$TARGET" == tests ]]   || \
   [[ "$TARGET" == *test_* ]] || \
   [[ "$TARGET" == *_test.py ]] || \
   [[ "$TARGET" == "." ]]; then
    if command -v pytest &>/dev/null; then
        run_check "pytest" pytest "$TARGET" -v
    else
        echo -e "${YELLOW}[pytest] not found, skipped${RESET}"
        echo
    fi
else
    echo -e "${YELLOW}[pytest] skipped for target '$TARGET'${RESET}"
    echo
fi

# --- Итог ---

echo -e "${BOLD}========================================${RESET}"
echo -e "${BOLD} Results: ${GREEN}$PASS passed${RESET} / ${RED}$FAIL failed${RESET}"
if [[ ${#ERRORS[@]} -gt 0 ]]; then
    echo -e "${RED} Failed: ${ERRORS[*]}${RESET}"
fi
echo -e "${BOLD}========================================${RESET}"

[[ $FAIL -eq 0 ]]
