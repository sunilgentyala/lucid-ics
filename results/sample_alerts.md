# Sample LUCID-ICS triage alerts (final trial, seed=1009)

## Window 3353 (t=16766s) -- recon_scan

- Risk score: 0.60, classifier confidence: 0.42
- ATT&CK for ICS: T0846 (Remote System Discovery)

**Narrative:** Something is probing this equipment the way an attacker maps out a network before an attack, not the way normal operations traffic behaves. Window 3353 (t=16766s) was flagged as 'recon_scan' with risk score 0.60 (classifier confidence 0.42). The strongest contributing signals were: spread of distinct register addresses touched in the window was elevated (+186.0 stdev from the learned normal-traffic baseline); number of distinct Modbus function codes used was elevated (+43.2 stdev from the learned normal-traffic baseline); number of distinct source hosts talking to the PLC was elevated (+18.2 stdev from the learned normal-traffic baseline). This pattern is consistent with MITRE ATT&CK for ICS technique T0846 (Remote System Discovery).

**Response playbook:**
- Identify and block the scanning source at the perimeter/segmentation firewall; OT networks should not see unsolicited function-code sweeps in normal operation.
- Review firewall/segmentation rules between IT and OT zones (Purdue Model boundary) for the path the scan traffic used.
- Treat as a precursor: increase monitoring sensitivity on the scanned assets for the following observation window.

---

## Window 3379 (t=16896s) -- sensor_spoofing

- Risk score: 0.32, classifier confidence: 0.58
- ATT&CK for ICS: T1692.002 (Unauthorized Message: Reporting Message (formerly 'Spoof Reporting Message', T0856))

**Narrative:** A sensor reading on this equipment does not match how the process normally behaves -- it may be reporting false data rather than the true process state. Window 3379 (t=16896s) was flagged as 'sensor_spoofing' with risk score 0.32 (classifier confidence 0.58). The strongest contributing signals were: variability of reported values within the window was suppressed (-3.2 stdev from the learned normal-traffic baseline); fraction of repeated/duplicate values was suppressed (-0.5 stdev from the learned normal-traffic baseline); largest single-step change in a reported value was elevated (+0.3 stdev from the learned normal-traffic baseline). This pattern is consistent with MITRE ATT&CK for ICS technique T1692.002 (Unauthorized Message: Reporting Message).

**Response playbook:**
- Cross-validate the reported sensor value against an independent estimate (e.g., a physics-based or redundant-sensor check) rather than trusting the single reading.
- Do not let the operator dashboard auto-acknowledge the deviation; require manual confirmation given the risk of a deception attack masking a real process excursion.
- Escalate to physical/process safety systems if plausible physical harm is possible.

---

## Window 3473 (t=17365s) -- dos_flood

- Risk score: 0.99, classifier confidence: 1.00
- ATT&CK for ICS: T0814 (Denial of Service)

**Narrative:** This equipment is being flooded with far more traffic than normal, which can slow down or block its real control commands. Window 3473 (t=17365s) was flagged as 'dos_flood' with risk score 0.99 (classifier confidence 1.00). The strongest contributing signals were: spread of distinct register addresses touched in the window was suppressed (-155.5 stdev from the learned normal-traffic baseline); average device response latency was elevated (+62.6 stdev from the learned normal-traffic baseline); tail (95th percentile) device response latency was elevated (+51.1 stdev from the learned normal-traffic baseline). This pattern is consistent with MITRE ATT&CK for ICS technique T0814 (Denial of Service).

**Response playbook:**
- Rate-limit or null-route the flooding source; confirm the PLC/RTU is still meeting its real-time control-loop deadlines and has not entered a fail-safe state.
- If response latency degraded control-loop timing, verify the process remained within safe bounds during the flood; do not assume 'no alarms' means 'no impact.'
- Capture flow statistics for the flood window to support upstream ISP/segment blocking.

---

## Window 3571 (t=17856s) -- unauthorized_write

- Risk score: 0.85, classifier confidence: 1.00
- ATT&CK for ICS: T1692.001 (Unauthorized Message: Command Message (formerly 'Unauthorized Command Message', T0855))

**Narrative:** Someone who is not the normal control system wrote a command to this equipment. Window 3571 (t=17856s) was flagged as 'unauthorized_write' with risk score 0.85 (classifier confidence 1.00). The strongest contributing signals were: writes to actuator registers from a source other than the authorized HMI was elevated (+72.8 stdev from the learned normal-traffic baseline); number of distinct Modbus function codes used was elevated (+21.6 stdev from the learned normal-traffic baseline); fraction of requests that were writes rather than reads was elevated (+21.1 stdev from the learned normal-traffic baseline). This pattern is consistent with MITRE ATT&CK for ICS technique T1692.001 (Unauthorized Message: Command Message).

**Response playbook:**
- Cross-check the writing source against the authorized engineering/HMI asset list; isolate the source host at the network layer if it is not on that list.
- Verify current actuator state against the last known-good setpoint before accepting further writes; consider a temporary read-only/monitor mode on the affected PLC.
- Preserve the command message and surrounding window for forensics (NIST SP 800-82 Rev.3 Sec.6, incident handling) before any device reboot.

---

## Window 4237 (t=21186s) -- replay

- Risk score: 0.48, classifier confidence: 0.55
- ATT&CK for ICS: T1692.001 (Unauthorized Message: Command Message (replayed))

**Narrative:** A previously seen command was sent again, out of its normal sequence -- consistent with an attacker replaying captured traffic rather than a real operator action. Window 4237 (t=21186s) was flagged as 'replay' with risk score 0.48 (classifier confidence 0.55). The strongest contributing signals were: spread of distinct register addresses touched in the window was suppressed (-9.1 stdev from the learned normal-traffic baseline); fraction of requests that were writes rather than reads was suppressed (-7.0 stdev from the learned normal-traffic baseline); variability of reported values within the window was suppressed (-6.4 stdev from the learned normal-traffic baseline). This pattern is consistent with MITRE ATT&CK for ICS technique T1692.001 (Unauthorized Message: Command Message (replayed)).

**Response playbook:**
- Check for duplicate/out-of-sequence message identifiers or timestamps inconsistent with the polling cycle -- a hallmark of replayed traffic.
- If the protocol lacks sequence numbers or freshness checks (as with legacy Modbus/TCP), flag the segment for a network-layer freshness control (e.g., an inline bump-in-the-wire monitor) rather than relying on the PLC alone.
- Rotate any session-level credentials on the affected link and confirm actuator state.

---

