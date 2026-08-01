# Sample LUCID-ICS triage alerts (final trial, seed=1009)

## Window 3353 (t=16766s) -- recon_scan

- Risk score: 0.60, classifier confidence: 0.42
- ATT&CK for ICS: T0846 (Remote System Discovery)

**Narrative:** Window 3353 (t=16766s) was flagged as 'recon_scan' with risk score 0.60 (classifier confidence 0.42). The strongest contributing signals were: spread of distinct register addresses touched in the window was elevated (+186.0 stdev from the learned normal-traffic baseline); number of distinct Modbus function codes used was elevated (+43.2 stdev from the learned normal-traffic baseline); number of distinct source hosts talking to the PLC was elevated (+18.2 stdev from the learned normal-traffic baseline). This pattern is consistent with MITRE ATT&CK for ICS technique T0846 (Remote System Discovery).

**Response playbook:**
- Identify and block the scanning source at the perimeter/segmentation firewall; OT networks should not see unsolicited function-code sweeps in normal operation.
- Review firewall/segmentation rules between IT and OT zones (Purdue Model boundary) for the path the scan traffic used.
- Treat as a precursor: increase monitoring sensitivity on the scanned assets for the following observation window.

---

## Window 3354 (t=16770s) -- recon_scan

- Risk score: 0.91, classifier confidence: 0.95
- ATT&CK for ICS: T0846 (Remote System Discovery)

**Narrative:** Window 3354 (t=16770s) was flagged as 'recon_scan' with risk score 0.91 (classifier confidence 0.95). The strongest contributing signals were: spread of distinct register addresses touched in the window was elevated (+474.9 stdev from the learned normal-traffic baseline); number of distinct Modbus function codes used was elevated (+43.2 stdev from the learned normal-traffic baseline); total number of protocol events was elevated (+19.8 stdev from the learned normal-traffic baseline). This pattern is consistent with MITRE ATT&CK for ICS technique T0846 (Remote System Discovery).

**Response playbook:**
- Identify and block the scanning source at the perimeter/segmentation firewall; OT networks should not see unsolicited function-code sweeps in normal operation.
- Review firewall/segmentation rules between IT and OT zones (Purdue Model boundary) for the path the scan traffic used.
- Treat as a precursor: increase monitoring sensitivity on the scanned assets for the following observation window.

---

## Window 3355 (t=16776s) -- recon_scan

- Risk score: 0.90, classifier confidence: 1.00
- ATT&CK for ICS: T0846 (Remote System Discovery)

**Narrative:** Window 3355 (t=16776s) was flagged as 'recon_scan' with risk score 0.90 (classifier confidence 1.00). The strongest contributing signals were: spread of distinct register addresses touched in the window was elevated (+449.6 stdev from the learned normal-traffic baseline); number of distinct Modbus function codes used was elevated (+43.2 stdev from the learned normal-traffic baseline); number of distinct source hosts talking to the PLC was elevated (+18.2 stdev from the learned normal-traffic baseline). This pattern is consistent with MITRE ATT&CK for ICS technique T0846 (Remote System Discovery).

**Response playbook:**
- Identify and block the scanning source at the perimeter/segmentation firewall; OT networks should not see unsolicited function-code sweeps in normal operation.
- Review firewall/segmentation rules between IT and OT zones (Purdue Model boundary) for the path the scan traffic used.
- Treat as a precursor: increase monitoring sensitivity on the scanned assets for the following observation window.

---

## Window 3356 (t=16780s) -- recon_scan

- Risk score: 0.90, classifier confidence: 0.96
- ATT&CK for ICS: T0846 (Remote System Discovery)

**Narrative:** Window 3356 (t=16780s) was flagged as 'recon_scan' with risk score 0.90 (classifier confidence 0.96). The strongest contributing signals were: spread of distinct register addresses touched in the window was elevated (+531.4 stdev from the learned normal-traffic baseline); number of distinct Modbus function codes used was elevated (+43.2 stdev from the learned normal-traffic baseline); total number of protocol events was elevated (+19.8 stdev from the learned normal-traffic baseline). This pattern is consistent with MITRE ATT&CK for ICS technique T0846 (Remote System Discovery).

**Response playbook:**
- Identify and block the scanning source at the perimeter/segmentation firewall; OT networks should not see unsolicited function-code sweeps in normal operation.
- Review firewall/segmentation rules between IT and OT zones (Purdue Model boundary) for the path the scan traffic used.
- Treat as a precursor: increase monitoring sensitivity on the scanned assets for the following observation window.

---

## Window 3357 (t=16786s) -- recon_scan

- Risk score: 0.91, classifier confidence: 1.00
- ATT&CK for ICS: T0846 (Remote System Discovery)

**Narrative:** Window 3357 (t=16786s) was flagged as 'recon_scan' with risk score 0.91 (classifier confidence 1.00). The strongest contributing signals were: spread of distinct register addresses touched in the window was elevated (+484.9 stdev from the learned normal-traffic baseline); number of distinct Modbus function codes used was elevated (+43.2 stdev from the learned normal-traffic baseline); number of distinct source hosts talking to the PLC was elevated (+18.2 stdev from the learned normal-traffic baseline). This pattern is consistent with MITRE ATT&CK for ICS technique T0846 (Remote System Discovery).

**Response playbook:**
- Identify and block the scanning source at the perimeter/segmentation firewall; OT networks should not see unsolicited function-code sweeps in normal operation.
- Review firewall/segmentation rules between IT and OT zones (Purdue Model boundary) for the path the scan traffic used.
- Treat as a precursor: increase monitoring sensitivity on the scanned assets for the following observation window.

---

## Window 3358 (t=16791s) -- recon_scan

- Risk score: 0.88, classifier confidence: 0.98
- ATT&CK for ICS: T0846 (Remote System Discovery)

**Narrative:** Window 3358 (t=16791s) was flagged as 'recon_scan' with risk score 0.88 (classifier confidence 0.98). The strongest contributing signals were: spread of distinct register addresses touched in the window was elevated (+442.3 stdev from the learned normal-traffic baseline); number of distinct Modbus function codes used was elevated (+43.2 stdev from the learned normal-traffic baseline); number of distinct source hosts talking to the PLC was elevated (+18.2 stdev from the learned normal-traffic baseline). This pattern is consistent with MITRE ATT&CK for ICS technique T0846 (Remote System Discovery).

**Response playbook:**
- Identify and block the scanning source at the perimeter/segmentation firewall; OT networks should not see unsolicited function-code sweeps in normal operation.
- Review firewall/segmentation rules between IT and OT zones (Purdue Model boundary) for the path the scan traffic used.
- Treat as a precursor: increase monitoring sensitivity on the scanned assets for the following observation window.

---

