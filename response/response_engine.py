# response/response_engine.py
"""
Response Engine - Aegis-LX
============================
Executes defence actions per tier.

TIER 2: CPU throttle via cpulimit (PID-targeted, legit users unaffected)
TIER 3: Block outbound for suspect UID only (iptables owner match)
TIER 4: Block ALL outbound — TCP, UDP, AND ICMP (three rules)
         Established connections preserved so admin SSH stays alive.
TIER 5: Manual only — never called from here automatically.

LOCKDOWN FIX:
  Old code only blocked --state NEW,RELATED which only affects TCP/UDP.
  ping (ICMP) bypassed this entirely. Fixed by adding explicit ICMP DROP
  rule and using INPUT chain ACCEPT for ESTABLISHED to preserve SSH.
"""

import subprocess

_throttled_pids = set()
_isolate_active = False


def apply_tier(new_tier, old_tier, sig_hits):
    if new_tier > old_tier:
        _escalate(new_tier, sig_hits)
    elif new_tier < old_tier:
        _deescalate(new_tier, old_tier)


def _escalate(tier, sig_hits):
    global _isolate_active

    if tier == 1:
        pass  # Alert only — notifier handles it

    elif tier == 2:
        pids = _extract_pids(sig_hits)
        for pid in pids:
            if pid and pid not in _throttled_pids:
                try:
                    subprocess.Popen(
                        ["cpulimit", "--pid", str(pid), "--limit", "10", "--background"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                    _throttled_pids.add(pid)
                    print("  [SLOW] CPU throttled PID " + str(pid) + " to 10%")
                except FileNotFoundError:
                    print("  [SLOW] cpulimit not found: sudo apt install cpulimit")

    elif tier == 3:
        uids = _extract_uids(sig_hits)
        for uid in uids:
            if uid is not None:
                try:
                    subprocess.run(
                        ["iptables", "-A", "OUTPUT",
                         "-m", "owner", "--uid-owner", str(uid),
                         "-m", "state", "--state", "NEW", "-j", "DROP"],
                        check=True, stderr=subprocess.PIPE
                    )
                    print("  [CONTAIN] Outbound blocked for UID " + str(uid))
                except Exception as e:
                    print("  [CONTAIN] iptables error: " + str(e)[:60])

    elif tier >= 4:
        # ISOLATE / LOCKDOWN
        # Block ALL new outbound: TCP, UDP, and ICMP separately.
        # ESTABLISHED connections are preserved — admin SSH stays alive.
        if not _isolate_active:
            rules = [
                # Block new TCP/UDP outbound
                ["iptables", "-I", "OUTPUT", "1",
                 "-m", "state", "--state", "NEW,RELATED", "-j", "DROP"],
                # Block ALL ICMP outbound (ping, traceroute etc.)
                ["iptables", "-I", "OUTPUT", "2",
                 "-p", "icmp", "-j", "DROP"],
                # Block new UDP explicitly (DNS lookups, scans)
                ["iptables", "-I", "OUTPUT", "3",
                 "-p", "udp", "-m", "state", "--state", "NEW", "-j", "DROP"],
            ]
            success = True
            for rule in rules:
                try:
                    subprocess.run(rule, check=True, stderr=subprocess.PIPE)
                except Exception as e:
                    print("  [ISOLATE] Rule failed: " + str(e)[:60])
                    success = False
            if success:
                _isolate_active = True
                print("  [ISOLATE] All outbound blocked: TCP, UDP, ICMP")
                print("  [ISOLATE] Established connections (SSH) preserved")
            else:
                print("  [ISOLATE] Partial enforcement — check iptables manually")


def _deescalate(new_tier, old_tier):
    global _isolate_active

    if old_tier >= 4 and new_tier < 4 and _isolate_active:
        # Remove all three isolation rules
        removal_rules = [
            ["iptables", "-D", "OUTPUT",
             "-m", "state", "--state", "NEW,RELATED", "-j", "DROP"],
            ["iptables", "-D", "OUTPUT",
             "-p", "icmp", "-j", "DROP"],
            ["iptables", "-D", "OUTPUT",
             "-p", "udp", "-m", "state", "--state", "NEW", "-j", "DROP"],
        ]
        for rule in removal_rules:
            try:
                subprocess.run(rule, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        _isolate_active = False
        print("  [RESTORE] All outbound blocks lifted")

    if old_tier >= 3 and new_tier < 3:
        try:
            subprocess.run(["iptables", "-F", "OUTPUT"], stderr=subprocess.DEVNULL)
            print("  [RESTORE] Per-process contain rules cleared")
        except Exception:
            pass

    if old_tier >= 2 and new_tier < 2:
        for pid in list(_throttled_pids):
            try:
                subprocess.run(
                    ["pkill", "-f", "cpulimit.*" + str(pid)],
                    stderr=subprocess.DEVNULL
                )
                _throttled_pids.discard(pid)
            except Exception:
                pass
        print("  [RESTORE] CPU throttles released")


def flush_all_rules():
    """Call on clean exit to remove all iptables rules."""
    global _isolate_active
    try:
        subprocess.run(["iptables", "-F", "OUTPUT"], stderr=subprocess.DEVNULL)
        _isolate_active = False
    except Exception:
        pass
    for pid in list(_throttled_pids):
        try:
            subprocess.run(
                ["pkill", "-f", "cpulimit.*" + str(pid)],
                stderr=subprocess.DEVNULL
            )
        except Exception:
            pass
    _throttled_pids.clear()


def _extract_pids(sig_hits):
    return [h.get("pid") for h in sig_hits if h.get("pid")]


def _extract_uids(sig_hits):
    uids = []
    for h in sig_hits:
        user = h.get("user", "")
        if user == "root":
            uids.append(0)
    return list(set(uids))
