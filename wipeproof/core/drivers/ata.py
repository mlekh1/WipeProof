"""
WipeProof ATA Sanitization Driver.

Implements ATA Sanitize Device (ACS-2+) and legacy ATA Secure Erase via hdparm.
Maps to NIST SP 800-88 Rev. 2 'Purge' / IEEE 2883:2022 Block Erase.
"""

from __future__ import annotations
import shutil
import subprocess
import time
from typing import Callable, Optional

from wipeproof.core.drivers.base import SanitizerDriver, DriverExecutionResult
from wipeproof.core.exceptions import DeviceLockedError, SanitizationFailedError
from wipeproof.core.models import (
    DeviceProfile,
    MediaType,
    SanitizationLevel,
    SanitizationMethod,
)


class AtaSanitizerDriver(SanitizerDriver):
    """Executes hardware ATA Sanitize or ATA Secure Erase commands."""

    def __init__(self, hdparm_path: Optional[str] = None):
        super().__init__("ATA Hardware Sanitize Driver (Purge)")
        self.hdparm_bin = hdparm_path or shutil.which("hdparm")

    def can_sanitize(self, device: DeviceProfile) -> bool:
        return device.media_type in (MediaType.SATA_SSD, MediaType.ROTATIONAL_HDD)

    def execute(
        self,
        device: DeviceProfile,
        dry_run: bool = False,
        progress_callback: Optional[Callable[[float, int, int], None]] = None,
    ) -> DriverExecutionResult:
        start_time = time.monotonic()

        if not self.hdparm_bin:
            raise SanitizationFailedError(
                "hdparm utility not found. ATA sanitize requires hdparm installed in PATH."
            )

        if dry_run:
            duration = round(time.monotonic() - start_time, 3)
            return DriverExecutionResult(
                success=True,
                method=SanitizationMethod.ATA_SANITIZE_BLOCK_ERASE,
                level=SanitizationLevel.PURGE,
                standard_reference="NIST_SP_800_88_REV_2_PURGE",
                command_executed=f"[DRY-RUN] hdparm --yes-i-know-what-i-am-doing --sanitize-block-erase {device.path}",
                firmware_status="DRY_RUN_SUCCESS",
                bytes_written=0,
                duration_seconds=duration,
                notes="Dry run of ATA Sanitize Block Erase.",
                disclaimer=None,
            )

        # Step 1: Check security freeze lock
        security_status = self._check_security_state(device.path)
        if "frozen" in security_status.lower() and "not frozen" not in security_status.lower():
            raise DeviceLockedError(
                f"Device {device.path} is in ATA Security FROZEN state. BIOS/UEFI locked the drive "
                "at boot. You must sleep/wake the system or hot-unplug/replug SATA power to unfreeze."
            )

        # Step 2: Attempt ATA Sanitize Block Erase first (Modern ACS-2 standard)
        sanitize_cmd = [
            self.hdparm_bin,
            "--yes-i-know-what-i-am-doing",
            "--sanitize-block-erase",
            device.path,
        ]
        res = subprocess.run(sanitize_cmd, capture_output=True, text=True, check=False)

        if res.returncode == 0:
            duration = round(time.monotonic() - start_time, 3)
            return DriverExecutionResult(
                success=True,
                method=SanitizationMethod.ATA_SANITIZE_BLOCK_ERASE,
                level=SanitizationLevel.PURGE,
                standard_reference="NIST_SP_800_88_REV_2_PURGE (IEEE 2883:2022 Block Erase)",
                command_executed=" ".join(sanitize_cmd),
                firmware_status="ATA_SANITIZE_BLOCK_ERASE_SUCCESS",
                bytes_written=device.size_bytes,
                duration_seconds=duration,
                notes="Modern ATA Sanitize Block Erase completed successfully.",
            )

        # Step 3: Fallback to Legacy ATA Enhanced Secure Erase
        # Requires temporary password setup
        temp_pass = "WipeProof987"
        set_pass_cmd = [
            self.hdparm_bin,
            "--user-master",
            "u",
            "--security-set-pass",
            temp_pass,
            device.path,
        ]
        set_res = subprocess.run(set_pass_cmd, capture_output=True, text=True, check=False)
        if set_res.returncode != 0:
            raise SanitizationFailedError(
                f"Failed to initiate ATA sanitize or set temporary password on {device.path}: {set_res.stderr.strip()}"
            )

        erase_cmd = [
            self.hdparm_bin,
            "--user-master",
            "u",
            "--security-erase-enhanced",
            temp_pass,
            device.path,
        ]
        erase_res = subprocess.run(erase_cmd, capture_output=True, text=True, check=False)
        duration = round(time.monotonic() - start_time, 3)

        if erase_res.returncode != 0:
            raise SanitizationFailedError(
                f"ATA Enhanced Secure Erase failed on {device.path}: {erase_res.stderr.strip()}"
            )

        return DriverExecutionResult(
            success=True,
            method=SanitizationMethod.ATA_SECURE_ERASE,
            level=SanitizationLevel.PURGE,
            standard_reference="NIST_SP_800_88_REV_2_PURGE (Legacy ATA Secure Erase)",
            command_executed=" ".join(erase_cmd),
            firmware_status="ATA_SECURITY_ERASE_SUCCESS",
            bytes_written=device.size_bytes,
            duration_seconds=duration,
            notes="Legacy ATA Enhanced Secure Erase completed successfully.",
        )

    def _check_security_state(self, device_path: str) -> str:
        """Inspect ATA security flags via hdparm -I."""
        if not self.hdparm_bin:
            return ""
        cmd = [self.hdparm_bin, "-I", device_path]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            return res.stdout
        except Exception:
            return ""
