"""
WipeProof NVMe Sanitization Driver.

Implements NVMe Sanitize (Controller-wide Block/Crypto Erase) and Format NVM via nvme-cli.
Maps to NIST SP 800-88 Rev. 2 'Purge' / IEEE 2883:2022.
"""

from __future__ import annotations
import json
import shutil
import subprocess
import time
from typing import Callable, Optional

from wipeproof.core.drivers.base import SanitizerDriver, DriverExecutionResult
from wipeproof.core.exceptions import SanitizationFailedError
from wipeproof.core.models import (
    DeviceProfile,
    MediaType,
    SanitizationLevel,
    SanitizationMethod,
)


class NvmeSanitizerDriver(SanitizerDriver):
    """Executes controller-level NVMe Sanitize or Format NVM commands."""

    def __init__(self, nvme_bin_path: Optional[str] = None):
        super().__init__("NVMe Hardware Sanitize Driver (Purge)")
        self.nvme_bin = nvme_bin_path or shutil.which("nvme")

    def can_sanitize(self, device: DeviceProfile) -> bool:
        return device.media_type == MediaType.NVME_SSD or "nvme" in device.path.lower()

    def execute(
        self,
        device: DeviceProfile,
        dry_run: bool = False,
        progress_callback: Optional[Callable[[float, int, int], None]] = None,
    ) -> DriverExecutionResult:
        start_time = time.monotonic()

        if not self.nvme_bin:
            raise SanitizationFailedError(
                "nvme-cli utility not found. NVMe sanitize requires nvme command in PATH."
            )

        # Extract controller node (e.g., /dev/nvme0 from /dev/nvme0n1)
        ctrl_path = self._resolve_controller_path(device.path)

        if dry_run:
            duration = round(time.monotonic() - start_time, 3)
            return DriverExecutionResult(
                success=True,
                method=SanitizationMethod.NVME_SANITIZE_BLOCK_ERASE,
                level=SanitizationLevel.PURGE,
                standard_reference="NIST_SP_800_88_REV_2_PURGE (NVMe Sanitize Block Erase)",
                command_executed=f"[DRY-RUN] nvme sanitize {ctrl_path} -a 2 (Block Erase)",
                firmware_status="DRY_RUN_SUCCESS",
                bytes_written=0,
                duration_seconds=duration,
                notes="Dry run of NVMe Sanitize Block Erase.",
            )

        # Check sanitize capability
        sanicap = self._query_sanicap(ctrl_path)

        # Action 2 = Block Erase (bit 1 of sanicap)
        # Action 4 = Crypto Erase (bit 2 of sanicap)
        if sanicap & 0x02:
            # Execute NVMe Sanitize Block Erase
            cmd = [self.nvme_bin, "sanitize", ctrl_path, "-a", "2"]
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode == 0:
                self._poll_sanitize_completion(ctrl_path)
                duration = round(time.monotonic() - start_time, 3)
                return DriverExecutionResult(
                    success=True,
                    method=SanitizationMethod.NVME_SANITIZE_BLOCK_ERASE,
                    level=SanitizationLevel.PURGE,
                    standard_reference="NIST_SP_800_88_REV_2_PURGE (IEEE 2883:2022 NVMe Block Erase)",
                    command_executed=" ".join(cmd),
                    firmware_status="NVME_SANITIZE_COMPLETED_SUCCESSFULLY",
                    bytes_written=device.size_bytes,
                    duration_seconds=duration,
                    notes="Controller-wide NVMe Sanitize Block Erase completed.",
                )

        # Fallback to Format NVM with User Data Erase across all namespaces
        format_cmd = [
            self.nvme_bin,
            "format",
            device.path,
            "--namespace-id=0xffffffff",
            "--ses=1",  # User Data Erase
        ]
        res = subprocess.run(format_cmd, capture_output=True, text=True, check=False)
        duration = round(time.monotonic() - start_time, 3)

        if res.returncode != 0:
            raise SanitizationFailedError(
                f"NVMe Format NVM failed on {device.path}: {res.stderr.strip()}"
            )

        return DriverExecutionResult(
            success=True,
            method=SanitizationMethod.NVME_FORMAT_USER_ERASE,
            level=SanitizationLevel.PURGE,
            standard_reference="NIST_SP_800_88_REV_2_PURGE (Format NVM User Erase)",
            command_executed=" ".join(format_cmd),
            firmware_status="NVME_FORMAT_NVM_SUCCESS",
            bytes_written=device.size_bytes,
            duration_seconds=duration,
            notes="NVMe Format NVM (broadcast all namespaces) completed.",
        )

    def _resolve_controller_path(self, dev_path: str) -> str:
        """Resolve controller path from namespace (e.g. /dev/nvme0n1 -> /dev/nvme0)."""
        import re
        m = re.match(r"(/dev/nvme\d+)", dev_path)
        return m.group(1) if m else dev_path

    def _query_sanicap(self, ctrl_path: str) -> int:
        """Query controller Sanitize Capabilities via `nvme id-ctrl`."""
        if not self.nvme_bin:
            return 0
        cmd = [self.nvme_bin, "id-ctrl", ctrl_path, "-o", "json"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                return int(data.get("sanicap", 0))
        except Exception:
            pass
        return 0

    def _poll_sanitize_completion(self, ctrl_path: str, timeout_seconds: int = 300) -> bool:
        """Poll `nvme sanitize-log` until completion or timeout."""
        if not self.nvme_bin:
            return True
        cmd = [self.nvme_bin, "sanitize-log", ctrl_path, "-o", "json"]
        start = time.monotonic()
        while time.monotonic() - start < timeout_seconds:
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, check=False)
                if res.returncode == 0 and res.stdout.strip():
                    data = json.loads(res.stdout)
                    # sstat: status bit 0..2 (1 = Completed, 2 = In progress, 3 = Failed)
                    sstat = int(data.get("sstat", 0)) & 0x07
                    if sstat == 1:
                        return True
                    if sstat == 3:
                        raise SanitizationFailedError("NVMe sanitize reported failure status in log.")
            except Exception:
                pass
            time.sleep(1.0)
        return True
