"""Static grounding knowledge for the explanation/triage layer.

Every attack family the detector can predict is mapped to (a) the closest
MITRE ATT&CK for ICS technique -- verified against attack.mitre.org rather
than recalled from memory, since ATT&CK IDs are frequently renumbered across
framework versions -- and (b) a short response playbook aligned with the
containment/eradication guidance structure in NIST SP 800-82 Rev. 3, "Guide
to Operational Technology (OT) Security" (Sept. 2023).

ATT&CK for ICS has no technique named exactly "replay"; a replayed
legitimate message is, from the target's point of view, an unauthorized
command or reporting message, so it is mapped to the closest applicable
technique with that caveat noted in `notes`.
"""
from __future__ import annotations

import dataclasses


@dataclasses.dataclass(frozen=True)
class TechniqueMapping:
    attack_type: str
    attck_id: str
    attck_name: str
    attck_url: str
    playbook: list[str]
    notes: str = ""


KNOWLEDGE_BASE: dict[str, TechniqueMapping] = {
    "unauthorized_write": TechniqueMapping(
        attack_type="unauthorized_write",
        attck_id="T1692.001",
        attck_name="Unauthorized Message: Command Message (formerly 'Unauthorized Command "
                    "Message', T0855)",
        attck_url="https://attack.mitre.org/techniques/T1692/001/",
        playbook=[
            "Cross-check the writing source against the authorized engineering/HMI asset list; "
            "isolate the source host at the network layer if it is not on that list.",
            "Verify current actuator state against the last known-good setpoint before accepting "
            "further writes; consider a temporary read-only/monitor mode on the affected PLC.",
            "Preserve the command message and surrounding window for forensics (NIST SP 800-82 "
            "Rev.3 Sec.6, incident handling) before any device reboot.",
        ],
    ),
    "replay": TechniqueMapping(
        attack_type="replay",
        attck_id="T1692.001",
        attck_name="Unauthorized Message: Command Message (replayed)",
        attck_url="https://attack.mitre.org/techniques/T1692/001/",
        playbook=[
            "Check for duplicate/out-of-sequence message identifiers or timestamps inconsistent "
            "with the polling cycle -- a hallmark of replayed traffic.",
            "If the protocol lacks sequence numbers or freshness checks (as with legacy Modbus/TCP), "
            "flag the segment for a network-layer freshness control (e.g., an inline bump-in-the-wire "
            "monitor) rather than relying on the PLC alone.",
            "Rotate any session-level credentials on the affected link and confirm actuator state.",
        ],
        notes="ATT&CK for ICS has no dedicated 'replay' technique; mapped to the closest applicable "
              "technique (Unauthorized Message: Command Message) since a replayed message is, from "
              "the target's perspective, an unauthorized command.",
    ),
    "sensor_spoofing": TechniqueMapping(
        attack_type="sensor_spoofing",
        attck_id="T1692.002",
        attck_name="Unauthorized Message: Reporting Message (formerly 'Spoof Reporting Message', "
                    "T0856)",
        attck_url="https://attack.mitre.org/techniques/T1692/002/",
        playbook=[
            "Cross-validate the reported sensor value against an independent estimate (e.g., a "
            "physics-based or redundant-sensor check) rather than trusting the single reading.",
            "Do not let the operator dashboard auto-acknowledge the deviation; require manual "
            "confirmation given the risk of a deception attack masking a real process excursion.",
            "Escalate to physical/process safety systems if plausible physical harm is possible.",
        ],
    ),
    "recon_scan": TechniqueMapping(
        attack_type="recon_scan",
        attck_id="T0846",
        attck_name="Remote System Discovery",
        attck_url="https://attack.mitre.org/techniques/T0846/",
        playbook=[
            "Identify and block the scanning source at the perimeter/segmentation firewall; "
            "OT networks should not see unsolicited function-code sweeps in normal operation.",
            "Review firewall/segmentation rules between IT and OT zones (Purdue Model boundary) "
            "for the path the scan traffic used.",
            "Treat as a precursor: increase monitoring sensitivity on the scanned assets for the "
            "following observation window.",
        ],
    ),
    "dos_flood": TechniqueMapping(
        attack_type="dos_flood",
        attck_id="T0814",
        attck_name="Denial of Service",
        attck_url="https://attack.mitre.org/techniques/T0814/",
        playbook=[
            "Rate-limit or null-route the flooding source; confirm the PLC/RTU is still meeting "
            "its real-time control-loop deadlines and has not entered a fail-safe state.",
            "If response latency degraded control-loop timing, verify the process remained within "
            "safe bounds during the flood; do not assume 'no alarms' means 'no impact.'",
            "Capture flow statistics for the flood window to support upstream ISP/segment blocking.",
        ],
    ),
}


def lookup(attack_type: str) -> TechniqueMapping | None:
    return KNOWLEDGE_BASE.get(attack_type)
