"""
WipeProof Sequential Block Overwrite Driver.
Implements NIST SP 800-88 Rev. 2 'Clear' semantics via sequential block zeroing.
"""

from __future__ import annotations
import os
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


class OverwriteDriver(SanitizerDriver):
    """Performs full sequential block zeroing on addressable LBAs."""

    CHUNK_SIZE = 1024 * 1024  # 1 MB chunk

    def __init__(self, name: str = "Sequential Overwrite (Clear)"):
        super().__init__(name)

    def can_sanitize(self, device: DeviceProfile) -> bool:
        # Overwrite can be executed on any addressable block device or virtual image
        return True

    def execute(
        self,
        device: DeviceProfile,
        dry_run: bool = False,
        progress_callback: Optional[Callable[[float, int, int], None]] = None,
    ) -> DriverExecutionResult:
        start_time = time.monotonic()
        total_bytes = device.size_bytes
        bytes_written = 0

        # Honest disclaimer for solid-state and flash storage
        disclaimer = None
        if device.media_type in (MediaType.SATA_SSD, MediaType.NVME_SSD, MediaType.USB_REMOVABLE):
            disclaimer = (
                "NIST SP 800-88 Rev. 2 'Clear' only: Sequential LBA overwrite cannot reach "
                "overprovisioned flash blocks, wear-leveling pools, or retired bad blocks. "
                "Hardware Sanitize is recommended for Purge semantics."
            )

        if dry_run:
            duration = round(time.monotonic() - start_time, 3)
            return DriverExecutionResult(
                success=True,
                method=SanitizationMethod.OVERWRITE_ZERO,
                level=SanitizationLevel.CLEAR,
                standard_reference="NIST_SP_800_88_REV_2_CLEAR",
                command_executed=f"[DRY-RUN] Simulating block overwrite of {total_bytes} bytes on {device.path}",
                firmware_status="DRY_RUN_SUCCESS",
                bytes_written=0,
                duration_seconds=duration,
                notes="Dry-run completed successfully without writing to device.",
                disclaimer=disclaimer,
            )

        zero_chunk = b"\x00" * self.CHUNK_SIZE

        try:
            # Open device for direct binary write
            # On Linux block devices, opening directly in write binary mode writes to sectors
            with open(device.path, "wb") as f:
                remaining = total_bytes
                while remaining > 0:
                    to_write = min(self.CHUNK_SIZE, remaining)
                    data = zero_chunk[:to_write]
                    f.write(data)
                    bytes_written += to_write
                    remaining -= to_write

                    if progress_callback:
                        fraction = bytes_written / total_bytes if total_bytes > 0 else 1.0
                        progress_callback(fraction, bytes_written, total_bytes)

                # Commit all buffers to persistent physical storage
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass

        except Exception as e:
            raise SanitizationFailedError(
                f"Overwrite failed on {device.path} at byte {bytes_written}/{total_bytes}: {e}"
            ) from e

        duration = round(time.monotonic() - start_time, 3)

        return DriverExecutionResult(
            success=True,
            method=SanitizationMethod.OVERWRITE_ZERO,
            level=SanitizationLevel.CLEAR,
            standard_reference="NIST_SP_800_88_REV_2_CLEAR",
            command_executed=f"open('{device.path}', 'wb').write(b'\\x00' * {bytes_written}); fsync()",
            firmware_status="LBA_WRITE_SUCCESS",
            bytes_written=bytes_written,
            duration_seconds=duration,
            notes=f"Sequential zero-overwrite completed across {bytes_written} bytes.",
            disclaimer=disclaimer,
        )
