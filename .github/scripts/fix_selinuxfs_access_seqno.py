#!/usr/bin/env python3
"""Sync sel_write_access() avd.seqno with fake_status (1) when ksu_selinux_hide_running is active."""
import pathlib
import re
import sys

selinuxfs = pathlib.Path("security/selinux/selinuxfs.c")
if not selinuxfs.is_file():
    print("ERROR: security/selinux/selinuxfs.c not found", file=sys.stderr)
    sys.exit(1)

text = selinuxfs.read_text()

pattern = re.compile(
    r"(length\s*=\s*scnprintf\s*\(\s*buf\s*,\s*SIMPLE_TRANSACTION_LIMIT\s*,\s*\n?\s*\"%x %x %x %x %u %x\")",
    re.MULTILINE,
)

if not pattern.search(text):
    print("ERROR: Could not find sel_write_access scnprintf in selinuxfs.c", file=sys.stderr)
    sys.exit(1)

spoof_block = (
    "#ifdef CONFIG_KSU_SUSFS\n"
    "\tif (ksu_selinux_hide_running && current_uid().val >= 10000)\n"
    "\t\tavd.seqno = 1;\n"
    "#endif\n\t"
)

if "avd.seqno = 1;" in text:
    print("[seqno-fix] avd.seqno = 1 already present in selinuxfs.c — checking for seccomp gate:")
    new_text, n = re.subn(
        r"&&\s*(?:current->seccomp\.mode\s*!=\s*SECCOMP_MODE_DISABLED|ksu_is_seccomp_enabled\(\))",
        "",
        text,
    )
    if n:
        selinuxfs.write_text(new_text)
        print(f"[seqno-fix] Removed {n} seccomp gate(s) in selinuxfs.c")
else:
    new_text, n = pattern.subn(spoof_block + r"\1", text, count=1)
    selinuxfs.write_text(new_text)
    print("[seqno-fix] Patched sel_write_access() in security/selinux/selinuxfs.c -> avd.seqno = 1 for uid >= 10000")
