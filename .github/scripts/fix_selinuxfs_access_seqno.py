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

# Ensure extern declaration exists if SUSFS didn't already add it
if "extern bool ksu_selinux_hide_running;" not in text:
    text = text.replace(
        "#include <linux/kernel.h>\n",
        "#include <linux/kernel.h>\n#ifdef CONFIG_KSU_SUSFS\nextern bool ksu_selinux_hide_running;\n#endif\n",
        1,
    )

# Locate sel_write_access() and patch right before the avd.seqno scnprintf
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
    print("[seqno-fix] avd.seqno = 1 already present in selinuxfs.c — check if it is seccomp-gated:")
    for i, line in enumerate(text.splitlines(), 1):
        if "avd.seqno" in line or "ksu_selinux_hide_running" in line:
            print(f"  selinuxfs.c:{i}: {line.strip()}")
    # Remove seccomp gate if one is guarding it
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
