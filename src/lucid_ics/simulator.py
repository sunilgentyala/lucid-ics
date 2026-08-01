"""Synthetic ICS/SCADA protocol-traffic simulator.

Generates Modbus/TCP-style protocol events (function code, register address,
value, response time) for a small closed-loop industrial process, plus five
injected attack families relevant to the MILCOM ICSCI workshop scope. This is
an original, fully synthetic testbed -- it is not derived from SWaT, WADI, or
any other public dataset -- built specifically because most public ICS
datasets are not redistributable and are too large to fetch inside this
project's build step. See paper Section IV-A for the disclosure and rationale.

Process model
-------------
A single control loop (tank level -> pump) with realistic sensor noise and a
PID-like controller, polled cyclically the way a real Modbus/TCP master
polls an RTU/PLC. Function codes follow the standard Modbus table:

    1  = Read Coils
    3  = Read Holding Registers
    5  = Write Single Coil
    6  = Write Single Register
    16 = Write Multiple Registers
"""
from __future__ import annotations

import dataclasses
import enum
from typing import Optional

import numpy as np
import pandas as pd

READ_COILS = 1
READ_HOLDING_REGISTERS = 3
WRITE_SINGLE_COIL = 5
WRITE_SINGLE_REGISTER = 6
WRITE_MULTIPLE_REGISTERS = 16

LEVEL_REG = 40001      # tank level sensor (read-only from the master's view)
FLOW_REG = 40002       # inflow rate sensor
PUMP_REG = 40003       # pump speed setpoint (actuator, normally written by the PLC/HMI only)
VALVE_COIL = 1         # outlet valve (actuator)

LEGITIMATE_SOURCE = "HMI-1"


class AttackType(str, enum.Enum):
    NORMAL = "normal"
    UNAUTHORIZED_WRITE = "unauthorized_write"
    REPLAY = "replay"
    SENSOR_SPOOFING = "sensor_spoofing"
    RECON_SCAN = "recon_scan"
    DOS_FLOOD = "dos_flood"


@dataclasses.dataclass
class SimulationConfig:
    duration_s: float = 3600.0
    poll_interval_s: float = 1.0
    jitter_s: float = 0.05
    setpoint: float = 60.0          # target tank level, percent
    noise_std: float = 0.4
    seed: int = 13
    # fraction of simulated *time* spent under attack; episodes are packed
    # into this budget so the setting is duration-independent (unlike a
    # fixed episode count, which either overflows very short runs or
    # under-covers very long ones).
    attack_time_fraction: float = 0.10
    attack_window_s: tuple[float, float] = (15.0, 90.0)
    normal_response_ms: tuple[float, float] = (2.0, 12.0)


class ICSProcessSimulator:
    """Simulates a polled Modbus control loop and injects labeled attacks."""

    def __init__(self, config: Optional[SimulationConfig] = None):
        self.cfg = config or SimulationConfig()
        self.rng = np.random.default_rng(self.cfg.seed)

    # -- physical process -------------------------------------------------
    def _run_process(self, n_steps: int) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        level = np.empty(n_steps)
        flow = np.empty(n_steps)
        pump = np.empty(n_steps)
        cur_level = self.cfg.setpoint
        integral = 0.0
        for i in range(n_steps):
            error = self.cfg.setpoint - cur_level
            integral = np.clip(integral + error * 0.01, -50, 50)
            pump_speed = np.clip(50 + 4.0 * error + 0.5 * integral, 0, 100)
            inflow = pump_speed * 0.018 + self.rng.normal(0, 0.05)
            outflow = 1.1 + self.rng.normal(0, 0.05)
            cur_level = np.clip(cur_level + inflow - outflow, 0, 100)
            level[i] = cur_level + self.rng.normal(0, self.cfg.noise_std)
            flow[i] = inflow
            pump[i] = pump_speed
        return level, flow, pump

    # -- attack scheduling --------------------------------------------------
    def _schedule_attacks(self, n_steps: int) -> list[tuple[int, int, AttackType]]:
        """Packs non-overlapping attack episodes into a time budget
        (`attack_time_fraction` of `n_steps`), cycling through all five
        families. Degrades gracefully on very short simulations (few or no
        episodes) instead of raising, since the budget -- not a fixed
        episode count -- drives how many episodes are attempted."""
        families = [
            AttackType.UNAUTHORIZED_WRITE,
            AttackType.REPLAY,
            AttackType.SENSOR_SPOOFING,
            AttackType.RECON_SCAN,
            AttackType.DOS_FLOOD,
        ]
        min_w, max_w = self.cfg.attack_window_s
        min_w_steps = max(1, int(min_w / self.cfg.poll_interval_s))
        max_w_steps = max(min_w_steps, int(max_w / self.cfg.poll_interval_s))
        budget_steps = int(n_steps * self.cfg.attack_time_fraction)

        used = np.zeros(n_steps, dtype=bool)
        episodes: list[tuple[int, int, AttackType]] = []
        used_steps = 0
        fam_i = 0
        attempts = 0
        max_attempts = 500

        while used_steps < budget_steps and attempts < max_attempts:
            attempts += 1
            width = min(int(self.rng.integers(min_w_steps, max_w_steps + 1)), max(n_steps - 2, 1))
            max_start = n_steps - width - 1
            if max_start <= 0:
                break
            start = int(self.rng.integers(0, max_start))
            end = start + width
            if used[start:end].any():
                continue
            used[start:end] = True
            episodes.append((start, end, families[fam_i % len(families)]))
            fam_i += 1
            used_steps += width

        episodes.sort(key=lambda e: e[0])
        return episodes

    # -- event stream generation -------------------------------------------
    def generate(self) -> pd.DataFrame:
        n_steps = int(self.cfg.duration_s / self.cfg.poll_interval_s)
        level, flow, pump = self._run_process(n_steps)
        episodes = self._schedule_attacks(n_steps)

        def active_attack(i: int) -> AttackType:
            for s, e, fam in episodes:
                if s <= i < e:
                    return fam
            return AttackType.NORMAL

        rows = []
        t = 0.0
        replay_buffer: list[dict] = []
        for i in range(n_steps):
            t += self.cfg.poll_interval_s + self.rng.normal(0, self.cfg.jitter_s)
            attack = active_attack(i)

            # 1) normal cyclic poll: read level + flow, then a control write
            resp_lo, resp_hi = self.cfg.normal_response_ms
            base_resp = self.rng.uniform(resp_lo, resp_hi)

            level_val = level[i]
            if attack == AttackType.SENSOR_SPOOFING:
                # deceptive drift injected into the *reported* sensor value
                # while the true process (pump/flow) keeps responding to the
                # real level -- classic OT deception-attack pattern.
                drift = min(20.0, 0.15 * (i - next(s for s, e, f in episodes if f == attack and s <= i < e)))
                level_val = level_val - drift

            rows.append(dict(t=t, src=LEGITIMATE_SOURCE, dst="PLC-1",
                              function_code=READ_HOLDING_REGISTERS, register=LEVEL_REG,
                              value=round(level_val, 2), response_time_ms=base_resp,
                              attack_type=attack.value))
            rows.append(dict(t=t + 0.01, src=LEGITIMATE_SOURCE, dst="PLC-1",
                              function_code=READ_HOLDING_REGISTERS, register=FLOW_REG,
                              value=round(flow[i], 3), response_time_ms=base_resp * 0.9,
                              attack_type=attack.value))
            rows.append(dict(t=t + 0.02, src=LEGITIMATE_SOURCE, dst="PLC-1",
                              function_code=WRITE_SINGLE_REGISTER, register=PUMP_REG,
                              value=round(pump[i], 2), response_time_ms=base_resp * 1.1,
                              attack_type=attack.value))

            if len(replay_buffer) < 200:
                replay_buffer.append(rows[-3])

            # 2) attack-specific injected traffic on top of the normal poll
            if attack == AttackType.UNAUTHORIZED_WRITE:
                rogue_val = float(self.rng.uniform(80, 100))
                rows.append(dict(t=t + 0.03, src="ENG-LAPTOP-7", dst="PLC-1",
                                  function_code=WRITE_MULTIPLE_REGISTERS, register=PUMP_REG,
                                  value=rogue_val, response_time_ms=self.rng.uniform(3, 9),
                                  attack_type=attack.value))
            elif attack == AttackType.REPLAY and replay_buffer:
                old = dict(self.rng.choice(replay_buffer))  # type: ignore[arg-type]
                old["t"] = t + 0.04
                old["attack_type"] = attack.value
                rows.append(old)
            elif attack == AttackType.RECON_SCAN:
                for fc in (READ_COILS, READ_HOLDING_REGISTERS, WRITE_SINGLE_COIL):
                    reg = int(self.rng.integers(40000, 40050))
                    rows.append(dict(t=t + self.rng.uniform(0.01, 0.05), src="UNKNOWN-192.168.1.211",
                                      dst="PLC-1", function_code=fc, register=reg,
                                      value=float(self.rng.integers(0, 2)),
                                      response_time_ms=self.rng.uniform(1, 4),
                                      attack_type=attack.value))
            elif attack == AttackType.DOS_FLOOD:
                for _ in range(int(self.rng.integers(6, 15))):
                    rows.append(dict(t=t + self.rng.uniform(0, 0.9), src="FLOOD-SRC",
                                      dst="PLC-1", function_code=READ_HOLDING_REGISTERS,
                                      register=LEVEL_REG, value=level_val,
                                      response_time_ms=self.rng.uniform(80, 400),
                                      attack_type=attack.value))

        df = pd.DataFrame(rows).sort_values("t").reset_index(drop=True)
        df["is_attack"] = (df["attack_type"] != AttackType.NORMAL.value).astype(int)
        return df


def generate_dataset(config: Optional[SimulationConfig] = None) -> pd.DataFrame:
    return ICSProcessSimulator(config).generate()
