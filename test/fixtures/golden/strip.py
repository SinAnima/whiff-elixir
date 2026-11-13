"""Remove host-dependent fields from a whiff report read on stdin."""
import json
import sys

SYSTEM = ["device", "inode", "links", "allocated_bytes", "sparse", "hidden", "readonly"]
SECURITY = ["mode", "permissions", "owner", "setuid", "setgid", "sticky", "acl", "xattrs"]

report = json.load(sys.stdin)
report.get("source", {}).pop("path", None)
report.get("temporal", {}).pop("filesystem", None)
for key in SYSTEM:
    report.get("system", {}).pop(key, None)
for key in SECURITY:
    report.get("security", {}).pop(key, None)
json.dump(report, sys.stdout, ensure_ascii=False, indent=1, sort_keys=True)
sys.stdout.write("\n")
