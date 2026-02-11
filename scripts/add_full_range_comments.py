#!/usr/bin/env python3
"""Insert '// Range cannot be verified (full use of range).' before each field whose constraint is full range (any value valid)."""
import re
import sys

# Ranges that mean "full use" (2^n - 1 for n bits): no verification possible
FULL_RANGE_PATTERN = re.compile(
    r'\s+\[0\.\.(?:1|3|7|15|31|63|127|255|65535)\];'
)
COMMENT = "// Range cannot be verified (full use of range)."

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "examples/asterix_family.dsl"
    with open(path, "r") as f:
        lines = f.readlines()

    out = []
    for i, line in enumerate(lines):
        prev = lines[i - 1].rstrip() if i > 0 else ""
        # Skip if this line is already the comment
        if COMMENT in line:
            out.append(line)
            continue
        # Field line with full range: has " [0..N];" and looks like a field (ident: type [constraint];)
        if FULL_RANGE_PATTERN.search(line) and re.search(r"^\s*\w+.*:\s*.*\[", line):
            # Only add if previous line is not already this comment
            if COMMENT not in prev:
                indent = line[: len(line) - len(line.lstrip())]
                out.append(f"{indent}{COMMENT}\n")
        out.append(line)

    with open(path, "w") as f:
        f.writelines(out)
    print(f"Updated {path}")

if __name__ == "__main__":
    main()
