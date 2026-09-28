"""
WipeProof Simulation & Loopback Driver.
Provides safe, deterministic, zero-risk sanitization simulation for CI, unit testing,
and reproducible demos without touching physical disks.
"""

from __future__ import annotations
import os
import time
from typing import Callable, Optional

from wipeproof.core.drivers.base import SanitizerDriver, DriverExecutionResult
from wipeproof.core.models import (
    DeviceProfile,
    MediaType,
    SanitizationLevel,
    SanitizationMethod,
)


class SimulationDriver(SanitizerDriver):
    """Safely sanitizes virtual loopback devices or sparse disk files."""

    def __init__(
        self,
        name: str = "Virtual Loopback Simulator",
        simulate_level: SanitizationLevel = SanitizationLevel.PURGE,
        simulate_method: SanitizationMethod = SanitizationMethod.SIMULATION_ERASE,
        fail_simulation: bool = False,
    ):
        super().__init__(name)
        self.simulate_level = simulate_level
        self.simulate_method = simulate_method
        self.fail_simulation = fail_simulation

    def can_sanitize(self, device: DeviceProfile) -> bool:
        return (
            device.media_type == MediaType.VIRTUAL_LOOPBACK
            or "loop" in device.path.lower()
            or device.path.endswith((".img", ".raw"))
            or "simulated" in device.path.lower()
        )

    def execute(
        self,
        device: DeviceProfile,
        dry_run: bool = False,
        progress_callback: Optional[Callable[[float, int, int], None]] = None,
    ) -> DriverExecutionResult:
        start_time = time.monotonic()

        if self.fail_simulation:
            return DriverExecutionResult(
                success=False,
                method=self.simulate_method,
                level=self.simulate_level,
                standard_reference="SIMULATION_FAILURE_INJECTED",
                command_executed="simulation_injected_error()",
                firmware_status="HARDWARE_ERROR_0xDEAD",
                bytes_written=0,
                duration_seconds=0.01,
                notes="Injected simulation error for negative test suite.",
            )

        if dry_run:
            duration = round(time.monotonic() - start_time, 3)
            return DriverExecutionResult(
                success=True,
                method=self.simulate_method,
                level=self.simulate_level,
                standard_reference="NIST_SP_800_88_REV_2_PURGE (Simulated)",
                command_executed=f"[DRY-RUN] Simulating sanitization on virtual target {device.path}",
                firmware_status="SIMULATION_DRY_RUN_SUCCESS",
                bytes_written=0,
                duration_seconds=duration,
                notes="Dry run completed on simulated disk.",
            )

        # If physical file exists, actually zero it out for verification testing
        bytes_written = 0
        if os.path.exists(device.path):
            file_size = os.path.getsize(device.path)
            chunk_size = 1024 * 64  # 64 KB
            zero_chunk = b"\x00" * chunk_size
            with open(device.path, "r+b") as f:
                remaining = file_size
                while remaining > 0:
                    write_len = min(chunk_size, remaining)
                    f.write(zero_chunk[:write_len])
                    bytes_written += write_len
                    remaining -= write_len
                    if progress_callback:
                        fraction = bytes_written / file_size if file_size > 0 else 1.0
                        progress_callback(fraction, bytes_written, file_size)
                f.flush()

        duration = round(time.monotonic() - start_time, 3)

        return DriverExecutionResult(
            success=True,
            method=self.simulate_method,
            level=self.simulate_level,
            standard_reference="NIST_SP_800_88_REV_2_PURGE (Simulated Block Erase)",
            command_executed=f"simulated_block_erase('{device.path}', size={bytes_written})",
            firmware_status="SIMULATION_SUCCESS_STATUS_0x00",
            bytes_written=bytes_written,
            duration_seconds=duration,
            notes="Simulated hardware block erase completed successfully on virtual image.",
        )
