"""Shared collection logic for TA-baseline (SecureBoot, lockdown, sshd, shadow, auditd)."""
import json
import os
import re
import subprocess
import sys

EFI_BOOTLOADER_CONTROL = (
    "/sys/firmware/efi/efivars/BootLoaderControl-8be4df61-93ca-11d2-aa0d-00e098032b8c"
)
LOCKDOWN_PATH = "/sys/kernel/security/lockdown"
SSH_BASE_CONFIG = "/etc/ssh/sshd_config"
SSH_DROPINS_DIR = "/etc/ssh/sshd_config.d"
SHADOW_PATH = "/etc/shadow"

PERMIT_RE = re.compile(r"^\s*PermitRootLogin\s+(\S+)", re.IGNORECASE)
PAUTH_RE = re.compile(r"^\s*PasswordAuthentication\s+(\S+)", re.IGNORECASE)


def read_file(path):
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError:
        return None


def read_secure_boot():
    try:
        with open(EFI_BOOTLOADER_CONTROL, "rb") as fh:
            raw = fh.read(4)
    except OSError:
        return "unknown"
    if len(raw) < 4:
        return "unknown"
    return "on" if int.from_bytes(raw, "little") & 0x1 else "off"


LOCKDOWN_MODES = {"none": 0, "integrity": 1, "confidentiality": 2}
LOCKDOWN_ACTIVE_RE = re.compile(r"[\[\(](none|integrity|confidentiality)[\]\)]")


def read_lockdown():
    content = read_file(LOCKDOWN_PATH)
    if content is None:
        return None
    m = LOCKDOWN_ACTIVE_RE.search(content)
    if m:
        return LOCKDOWN_MODES[m.group(1)]
    if "confidentiality" in content:
        return 2
    if "integrity" in content:
        return 1
    return None


def read_sshd_settings():
    files = [SSH_BASE_CONFIG]
    try:
        names = sorted(os.listdir(SSH_DROPINS_DIR))
    except OSError:
        names = []
    files.extend(os.path.join(SSH_DROPINS_DIR, n) for n in names if n.endswith(".conf"))
    permit = None
    pauth = None
    for path in files:
        content = read_file(path)
        if content is None:
            continue
        for line in content.splitlines():
            m = PERMIT_RE.match(line)
            if m:
                permit = m.group(1).lower()
            m = PAUTH_RE.match(line)
            if m:
                pauth = m.group(1).lower()
    permit_norm = "unknown"
    if permit == "yes":
        permit_norm = "yes"
    elif permit in ("prohibit-password", "without-password", "no"):
        permit_norm = "no"
    pauth_norm = "unknown"
    if pauth in ("yes", "no"):
        pauth_norm = pauth
    return permit_norm, pauth_norm


def read_shadow_aging():
    rec = {}
    content = read_file(SHADOW_PATH)
    if not content:
        return rec
    fields = content.splitlines()[0].split(":")
    if len(fields) >= 5:
        for idx, key in ((3, "shadow_min_age"), (4, "shadow_max_age")):
            v = fields[idx].strip()
            if v.isdigit():
                rec[key] = int(v)
    return rec


def read_auditd_active():
    try:
        p = subprocess.run(
            ["systemctl", "is-active", "auditd"],
            capture_output=True,
            text=True,
            timeout=25,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 0
    return 1 if p.stdout.strip() == "active" else 0


def discover():
    try:
        return _discover()
    except Exception:
        return {"status": "ok", "secure_boot": "unknown", "weak_ssh": 0, "auditd_active": 0}


def _discover():
    rec = {}
    rec["secure_boot"] = read_secure_boot()
    lockdown = read_lockdown()
    if lockdown is not None:
        rec["lockdown"] = lockdown
    permit, pauth = read_sshd_settings()
    rec["permit_root_login"] = permit
    rec["password_auth"] = pauth
    rec["weak_ssh"] = 1 if (permit == "yes" or pauth == "yes") else 0
    rec.update(read_shadow_aging())
    rec["auditd_active"] = read_auditd_active()
    rec["status"] = "alarm" if rec["weak_ssh"] == 1 else "ok"
    return rec


def metrics_payload(data):
    payload = {}
    sb = data.get("secure_boot")
    if sb in ("on", "off"):
        payload["secure_boot"] = 1 if sb == "on" else 0
    for key in ("lockdown", "weak_ssh", "auditd_active", "shadow_min_age", "shadow_max_age"):
        v = data.get(key)
        if v is not None:
            payload[key] = v
    return payload


def emit(payload):
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    sys.stdout.flush()


def fail(message):
    sys.stderr.write("TA-baseline collection error: %s\n" % message)
    return 1
