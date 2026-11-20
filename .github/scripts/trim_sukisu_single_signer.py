#!/usr/bin/env python3
"""Single-signer trim for SukiSU-Nova `builtin-new`-style apk_sign.c.

Layout handled: is_manager_apk() is a chain of `if check_v2_signature`
blocks, one per accepted manager signer (no apk_sign_keys[] table).
Keeps only the block that uses EXPECTED_SIZE / EXPECTED_HASH (the value the
Makefile sets for the SukiSU key) and removes the others.
"""
import re
import sys
from pathlib import Path

BLOCK_RE = re.compile(
    r'(?P<comment>(?:[ \t]*//[^\n]*\n)*)'
    r'[ \t]*if[ \t]*\([ \t]*check_v2_signature[ \t]*\((?P<args>[^()]*)\)[ \t]*\)'
    r'[ \t]*\n?[ \t]*return[ \t]+true;[ \t]*\n(?:[ \t]*\n)?')
FUNC_RE = re.compile(r'bool\s+is_manager_apk\s*\(\s*char\s*\*\s*path\s*\)\s*\{')


def die(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def func_span(text):
    m = FUNC_RE.search(text)
    if not m:
        die("is_manager_apk() not found")
    depth, i = 1, m.end()
    while i < len(text) and depth:
        depth += {'{': 1, '}': -1}.get(text[i], 0)
        i += 1
    if depth:
        die("unbalanced braces in is_manager_apk()")
    return m.end(), i - 1  # body without outer braces


def main():
    if len(sys.argv) != 2:
        die("usage: trim_sukisu_single_signer.py <root_dir>")
    path = Path(sys.argv[1]) / "kernel" / "manager" / "apk_sign.c"
    if not path.is_file():
        die(f"{path} not found")
    text = path.read_text(encoding="utf-8")
    if re.search(r'apk_sign_keys\s*\[\s*\]', text):
        die("apk_sign_keys[] table present; use trim_sukisu_managers.py instead")

    start, end = func_span(text)
    body = text[start:end]
    blocks = list(BLOCK_RE.finditer(body))
    if not blocks:
        die("no check_v2_signature blocks found in is_manager_apk()")
    keep = [b for b in blocks
            if 'EXPECTED_SIZE' in b.group('args') and 'EXPECTED_HASH' in b.group('args')]
    if len(keep) != 1:
        die(f"expected exactly one EXPECTED_SIZE/EXPECTED_HASH block, found {len(keep)}")
    drop = [b for b in blocks if b is not keep[0]]
    if not drop:
        print("already single-signer; nothing to do")
        return

    new_body = body
    for b in reversed(drop):
        print("removing:", " ".join(b.group('args').split())[:90])
        new_body = new_body[:b.start()] + new_body[b.end():]

    # post-conditions: exactly one check_v2_signature call left, and it is ours
    calls = re.findall(r'check_v2_signature\s*\(', new_body)
    if len(calls) != 1 or 'EXPECTED_HASH' not in new_body or 'return false;' not in new_body:
        die("post-check failed; file left untouched")
    path.write_text(text[:start] + new_body + text[end:], encoding="utf-8")
    print(f"trimmed {path}: removed {len(drop)} extra signer(s), kept the Makefile key")


if __name__ == "__main__":
    main()
