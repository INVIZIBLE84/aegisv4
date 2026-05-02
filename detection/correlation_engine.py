# detection/correlation_engine.py
"""
Alert Correlation Engine - Aegis-LX
======================================
Groups alerts from multiple detection engines within a time window
into composite threat assessments.

WHY THIS MATTERS:
  Each engine individually detects one signal. But real attacks leave
  multiple signals across different engines simultaneously.

  Example:
    - Signature engine sees nmap (RECON, score 20)
    - FIM engine sees /etc/shadow opened 30 seconds later
    - Stat engine sees diversity burst

  Individually each might be Tier 1-2. Together they are a clear
  attack progression. The correlation engine raises the composite
  to Tier 3 and generates a single high-confidence alert.

CORRELATION RULES:
  2 engines triggered within window  → escalate 1 tier above highest
  3+ engines triggered within window → escalate 2 tiers above highest
  Same kill chain phase from 2+ engines → CONFIRMED indicator
  Multiple phases (kill chain progression) → CRITICAL escalation

CORRELATION WINDOW: 90 seconds
"""

import time
from collections import defaultdict

CORRELATION_WINDOW = 90    # seconds

# How many extra tiers to add based on correlation count
CORRELATION_BONUS = {
    2: 1,   # 2 engines firing = +1 tier
    3: 2,   # 3 engines firing = +2 tiers
    4: 2,   # 4 engines firing = +2 tiers (cap at +2)
}

# Phase progression that indicates active kill chain movement
# If these phases appear together in the window = critical
KILL_CHAIN_PROGRESSIONS = [
    {"RECON", "CREDENTIAL"},         # scan then credential access
    {"RECON", "EXECUTION"},          # scan then exploit
    {"DISCOVERY", "CREDENTIAL"},     # enum then steal creds
    {"CREDENTIAL", "EXECUTION"},     # steal creds then execute
    {"CREDENTIAL", "PERSISTENCE"},   # steal creds then persist
    {"EXECUTION", "EXFILTRATION"},   # execute then exfil
    {"DISCOVERY", "PERSISTENCE"},    # enum then persist
]


class CorrelationEngine:
    """
    Receives alerts from all detection engines each cycle.
    Maintains a sliding window of recent alerts.
    Produces composite correlation alerts when multiple engines fire.
    """

    def __init__(self):
        # List of (timestamp, alert_dict) tuples
        self.alert_window = []
        self.MAX_WINDOW   = 500   # cap memory

        # Track last composite alert time to avoid spam
        self.last_composite_time = 0
        self.COMPOSITE_COOLDOWN  = 60   # seconds between composite alerts

    def ingest(self, engine_name, alerts):
        """
        Feed alerts from one engine into the correlation window.
        Call this for every engine's output each cycle.
        """
        now = time.time()
        for alert in alerts:
            self.alert_window.append({
                "time":    now,
                "engine":  engine_name,
                "phase":   alert.get("phase", "SAFE"),
                "tier":    alert.get("tier", 0),
                "detail":  alert.get("detail", ""),
                "process": alert.get("process", alert.get("process_name", "")),
            })

        # Trim old entries outside window
        self.alert_window = [
            a for a in self.alert_window
            if now - a["time"] <= CORRELATION_WINDOW
        ]

        # Cap size
        if len(self.alert_window) > self.MAX_WINDOW:
            self.alert_window = self.alert_window[-self.MAX_WINDOW:]

    def analyze(self):
        """
        Analyze the current alert window for correlated patterns.
        Returns a list of composite alert dicts (usually 0 or 1).
        """
        now = time.time()
        if not self.alert_window:
            return []

        # Group by engine
        engines_fired   = set(a["engine"] for a in self.alert_window)
        phases_seen     = set(a["phase"] for a in self.alert_window
                             if a["phase"] not in ("SAFE", ""))
        highest_tier    = max((a["tier"] for a in self.alert_window), default=0)
        engine_count    = len(engines_fired)

        # Need at least 2 engines to correlate
        if engine_count < 2:
            return []

        # Cooldown check
        if now - self.last_composite_time < self.COMPOSITE_COOLDOWN:
            return []

        # Determine correlation strength
        bonus = CORRELATION_BONUS.get(engine_count, 2)

        # Check for kill chain progression (strongest signal)
        chain_match = None
        for progression in KILL_CHAIN_PROGRESSIONS:
            if progression.issubset(phases_seen):
                chain_match = progression
                bonus = max(bonus, 2)   # guarantee +2 for confirmed progression
                break

        # Calculate composite tier (cap at 4 — tier 5 still manual only)
        composite_tier = min(highest_tier + bonus, 4)

        # Only alert if composite is higher than any individual alert
        if composite_tier <= highest_tier:
            return []

        self.last_composite_time = now

        # Build summary
        engines_str = " + ".join(sorted(engines_fired))
        phases_str  = " → ".join(sorted(phases_seen))

        if chain_match:
            detail = (
                "KILL CHAIN CONFIRMED: " + str(sorted(chain_match)) +
                " | Engines: " + engines_str +
                " | " + str(len(self.alert_window)) + " signals in " +
                str(CORRELATION_WINDOW) + "s window"
            )
            mitre = "Multiple: " + phases_str
        else:
            detail = (
                "MULTI-ENGINE CORRELATION: " + str(engine_count) +
                " engines triggered | Engines: " + engines_str +
                " | Phases: " + phases_str +
                " | " + str(len(self.alert_window)) + " signals in " +
                str(CORRELATION_WINDOW) + "s"
            )
            mitre = "Correlated: " + phases_str

        return [{
            "source":        "CORRELATION",
            "engine_count":  engine_count,
            "engines_fired": sorted(engines_fired),
            "phases_seen":   sorted(phases_seen),
            "chain_match":   sorted(chain_match) if chain_match else None,
            "signal_count":  len(self.alert_window),
            "phase":         "EXECUTION" if chain_match else sorted(phases_seen)[-1],
            "tier":          composite_tier,
            "mitre":         mitre,
            "detail":        detail,
            "timestamp":     time.strftime("%Y-%m-%d %H:%M:%S"),
        }]

    def get_window_summary(self):
        """Returns a brief summary string for the SOC dashboard."""
        if not self.alert_window:
            return "No signals in correlation window"
        engines = set(a["engine"] for a in self.alert_window)
        phases  = set(a["phase"] for a in self.alert_window
                     if a["phase"] not in ("SAFE",""))
        return (str(len(self.alert_window)) + " signals | " +
                str(len(engines)) + " engines | phases: " +
                (", ".join(sorted(phases)) if phases else "none"))
