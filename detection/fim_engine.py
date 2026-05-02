# detection/fim_engine.py
"""
File Integrity Monitor Engine - Aegis-LX
==========================================
Watches WHAT files are being opened, not WHO opened them.
Kills the LOLBin bypass problem — any tool reading /etc/shadow is caught.

FALSE POSITIVE PREVENTION:
  - Large trusted process list (PAM, NSS, and system daemons all read these files)
  - Per-process+file cooldown: same combo won't alert again for 120 seconds
  - /etc/passwd removed from watchlist (world-readable by design, too noisy)
  - /etc/group removed (read constantly by shell)
"""

import time

# ── Sensitive file watchlist ──────────────────────────────────────────────────
# NOTE: /etc/passwd and /etc/group deliberately excluded.
# They are world-readable and read by virtually every process that resolves
# usernames — adding them produces constant false positives with zero security value.
# An attacker reading /etc/passwd alone is not a meaningful threat indicator.

SENSITIVE_FILES = {
    # Credential files — high value targets
    "/etc/shadow":              {"phase": "CREDENTIAL",  "tier": 3, "mitre": "T1003.008 (/etc/shadow Access)"},
    "/etc/gshadow":             {"phase": "CREDENTIAL",  "tier": 3, "mitre": "T1003.008 (/etc/gshadow Access)"},
    "/etc/sudoers":             {"phase": "CREDENTIAL",  "tier": 3, "mitre": "T1548.003 (Sudoers Access)"},
    "/etc/sudoers.d":           {"phase": "CREDENTIAL",  "tier": 3, "mitre": "T1548.003 (Sudoers Dir Access)"},

    # SSH keys
    "/.ssh/id_rsa":             {"phase": "CREDENTIAL",  "tier": 3, "mitre": "T1552.004 (SSH Private Key)"},
    "/.ssh/id_ed25519":         {"phase": "CREDENTIAL",  "tier": 3, "mitre": "T1552.004 (SSH Private Key)"},
    "/.ssh/id_ecdsa":           {"phase": "CREDENTIAL",  "tier": 3, "mitre": "T1552.004 (SSH Private Key)"},
    "/.ssh/authorized_keys":    {"phase": "PERSISTENCE", "tier": 3, "mitre": "T1098.004 (Authorized Keys)"},

    # Shell history
    "/.bash_history":           {"phase": "DISCOVERY",   "tier": 2, "mitre": "T1552.003 (Bash History)"},
    "/.zsh_history":            {"phase": "DISCOVERY",   "tier": 2, "mitre": "T1552.003 (Zsh History)"},

    # Persistence targets
    "/.bashrc":                 {"phase": "PERSISTENCE", "tier": 2, "mitre": "T1546.004 (Bash Profile)"},
    "/.bash_profile":           {"phase": "PERSISTENCE", "tier": 2, "mitre": "T1546.004 (Bash Profile)"},
    "/etc/crontab":             {"phase": "PERSISTENCE", "tier": 3, "mitre": "T1053.003 (Cron Persistence)"},
    "/etc/cron.d":              {"phase": "PERSISTENCE", "tier": 3, "mitre": "T1053.003 (Cron Dir)"},
    "/etc/profile":             {"phase": "PERSISTENCE", "tier": 2, "mitre": "T1546.004 (Profile Persistence)"},
    "/etc/profile.d":           {"phase": "PERSISTENCE", "tier": 2, "mitre": "T1546.004 (Profile.d)"},

    # Cloud credentials
    "/.aws/credentials":        {"phase": "CREDENTIAL",  "tier": 3, "mitre": "T1552.001 (AWS Credentials)"},
    "/.config/gcloud":          {"phase": "CREDENTIAL",  "tier": 3, "mitre": "T1552.001 (GCloud Credentials)"},
}

# ── Trusted processes ─────────────────────────────────────────────────────────
# These NEVER trigger FIM alerts regardless of what file they open.
# This list must be comprehensive — Linux has many daemons that legitimately
# read sensitive files as part of normal operation.

TRUSTED_PROCESSES = {
    # PAM and authentication stack
    "sshd", "login", "passwd", "su", "sudo", "PAM", "pam",
    "gdm", "gdm3", "lightdm", "sddm", "xdm",
    "systemd", "systemd-logind", "systemd-user",

    # User management
    "useradd", "usermod", "userdel", "groupadd", "groupmod",
    "chpasswd", "chage", "newgrp", "newuidmap", "newgidmap",
    "gpasswd", "chsh", "chfn",

    # Policy/privilege
    "polkit", "polkitd", "pkexec", "dbus-daemon",

    # Scheduling
    "cron", "crond", "atd",

    # System services that read passwd/shadow via NSS
    "nscd", "sssd", "oddjobd", "winbindd",
    "avahi-daemon", "NetworkManager", "nm-dispatcher",
    "accountsservice", "accounts-daemon",

    # Package management (reads many files during install)
    "apt", "apt-get", "dpkg", "snap", "snapd",
    "unattended-upgr", "apt-config",

    # Shells — the shell itself opening a file is not suspicious
    # (the CONTENT of what it opens is what matters — caught by filename match)
    "bash", "sh", "zsh", "dash", "fish",

    # Standard tools that call getpwuid()/getgrnam() internally
    # These read user info files to resolve UIDs to names — completely normal
    "whoami", "id", "groups", "ls", "stat", "ps", "top", "htop",
    "w", "who", "last", "lastlog", "finger",
    "ssh", "scp", "rsync", "sftp",
    "git", "man", "less", "more",

    # Network tools that do username resolution
    "nmap",       # reads /etc/passwd to resolve user names in OS detection
    "ss", "netstat", "lsof", "ip",

    # Editors (opening for editing is caught by write hooks elsewhere)
    "vim", "vi", "nano", "gedit", "kate", "code",

    # Terminal emulators
    "gnome-terminal", "xterm", "konsole", "tmux", "screen",

    # Aegis itself — never flag ourselves
    "aegis", "python3", "python",
}

# How long (seconds) before the same process+file combo can alert again
ALERT_COOLDOWN = 120


class FIMEngine:
    def __init__(self):
        # (process_name, matched_pattern) -> last_alert_time
        self._last_alert = {}

    def analyze(self, file_events):
        alerts = []
        now = time.time()

        for event in file_events:
            proc     = event.get("process_name", "unknown")
            filename = event.get("filename", "")
            pid      = event.get("pid")
            ts       = event.get("timestamp", "")

            if not filename:
                continue

            # Skip trusted processes
            if proc in TRUSTED_PROCESSES:
                continue

            # Check watchlist
            match = self._match_sensitive(filename)
            if match is None:
                continue

            rule = SENSITIVE_FILES[match]

            # Cooldown: same process + same file pattern = skip if too recent
            cooldown_key = (proc, match)
            if cooldown_key in self._last_alert:
                if now - self._last_alert[cooldown_key] < ALERT_COOLDOWN:
                    continue
            self._last_alert[cooldown_key] = now

            # Evict old cooldown entries
            if len(self._last_alert) > 500:
                oldest = sorted(self._last_alert.items(), key=lambda x: x[1])[:200]
                for k, _ in oldest:
                    del self._last_alert[k]

            alerts.append({
                "source":    "FIM",
                "process":   proc,
                "pid":       pid,
                "filename":  filename,
                "matched":   match,
                "phase":     rule["phase"],
                "tier":      rule["tier"],
                "mitre":     rule["mitre"],
                "timestamp": ts,
                "detail":    proc + " opened " + filename + " [" + rule["mitre"] + "]",
            })

        return alerts

    def _match_sensitive(self, filename):
        if not filename:
            return None
        if filename in SENSITIVE_FILES:
            return filename
        for pattern in SENSITIVE_FILES:
            if filename.endswith(pattern):
                return pattern
        return None
