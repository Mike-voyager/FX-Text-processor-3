# Epson FX-890 Compatibility Guide

## Overview
This document describes compatibility between `src/model/enums.py` and Epson FX-890 (9-pin dot matrix printer).

## Fully Compatible Commands (100%)
- ✅ Initialization: ESC @, FF, CR, LF, BEL
- ✅ Fonts: ESC k n
- ✅ CPI: ESC P, ESC M, ESC g, SI, DC2
- ✅ Line spacing: ESC 2, ESC 0, ESC 1, ESC 3 n
- ✅ Text styles: ESC E/F, ESC 4/5, ESC -/-, ESC G/H, etc.
- ✅ Graphics (9-pin): ESC K, ESC L, ESC Y, ESC Z
- ✅ Paper sources: ESC EM n
- ✅ Print direction: ESC U n

## Commands with Fallback
### CodePage (use `to_escp_fx890()`)
- PC437 → ESC t 0
- PC850/PC858 → ESC t 2
- PC866/PC852 → fallback to PC437 (ESC t 0)

### GraphicsMode (use `to_escp_fx890()`)
- ESC * 0-6 modes → fallback to ESC K/L/Y/Z

## Usage Example
from src.model.enums import CodePage, GraphicsMode, validate_fx890_compatibility

Check compatibility
valid, error = validate_fx890_compatibility(
GraphicsMode.DOUBLE_DENSITY,
CodePage.PC437
)

if valid:
# Generate FX-890 compatible commands
codepage_cmd = CodePage.PC437.to_escp_fx890()
graphics_cmd = GraphicsMode.DOUBLE_DENSITY.to_escp_fx890(100)
else:
print(f"Warning: {error}")
undefined
