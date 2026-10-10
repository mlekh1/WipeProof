"""
WipeProof Safety Gatekeeper & Failsafe Enforcement.

Enforces defense-in-depth safety invariants:
1. Root / Boot disk rejection: Never wipe /, /boot, /home, or active swap.
2. Active mountpoint rejection: Never wipe a device with mounted partitions.
3. Virtual isolation: Destructive testing is strictly restricted to loopback/mock devices.
4. Typed confirmation: Interactive challenges requiring exact serial number confirmation.
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import Optional

from wipeproof.core.exceptions import SafetyViolationError
from wipeproof.core.models import DeviceProfile, MediaType

# Critical mount paths that must NEVER be on a targeted device
FORBIDDEN_MOUNTS = {
    "/",
    "/boot",
    "/boot/efi",
    "/etc",
    "/usr",
    "/var",
    "/home",
    "[SWAP]",
}


class SafetyGatekeeper:
    """Evaluates safety invariants before any destructive disk operation."""

    def __init__(self, test_mode_loopback_only: bool = False):
        """
        Args:
            test_mode_loopback_only: If True, only virtual loopback devices
                or simulated sparse image files are permitted. Touching real
                disks will raise a SafetyViolationError immediately.
        """
        self.test_mode_loopback_only = test_mode_loopback_only

    def evaluate_target_safety(self, device: DeviceProfile) -> None:
        """Run all safety checks against the device profile.
        
        Raises:
            SafetyViolationError: If any safety rule is violated.
        """
        # Rule 1: Loopback isolation check during test runs
        if self.test_mode_loopback_only:
            self._verify_loopback_isolation(device)

        # Rule 2: Root / Boot / System mountpoint interlock
        self._verify_no_forbidden_mounts(device)

        # Rule 3: Any active mount interlock
        self._verify_unmounted(device)

        # Rule 4: Read-only hardware interlock
        if device.is_read_only:
            raise SafetyViolationError(
                f"Device {device.path} is marked read-only by the kernel/hardware."
            )

    def _verify_loopback_isolation(self, device: DeviceProfile) -> None:
        """Ensure that in test mode, only loopback/virtual devices are touched."""
        is_loop = (
            device.media_type == MediaType.VIRTUAL_LOOPBACK
            or "loop" in device.path.lower()
            or device.path.endswith(".img")
            or device.path.endswith(".raw")
            or "simulated" in device.path.lower()
            or "mock" in device.path.lower()
        )
        if not is_loop:
            raise SafetyViolationError(
                f"CRITICAL SAFETY ABORT: Test suite attempted to target real disk {device.path} "
                f"({device.model}, {device.serial}). Destructive tests MUST only run on loopback "
                f"or simulated virtual images."
            )

    def _verify_no_forbidden_mounts(self, device: DeviceProfile) -> None:
        """Check if device or any of its partitions host critical OS mount points."""
        # Check explicit mountpoints in profile
        for mp in device.mountpoints:
            if mp in FORBIDDEN_MOUNTS or any(mp.startswith(f + "/") for f in FORBIDDEN_MOUNTS):
                raise SafetyViolationError(
                    f"CRITICAL SAFETY ABORT: Device {device.path} is hosting critical system "
                    f"mount point '{mp}'. WipeProof refuses to wipe OS / boot disks."
                )

        # On Linux, also check /proc/mounts directly for defense-in-depth
        active_mounts = self._get_live_system_mounts()
        dev_base = os.path.basename(device.path)

        for source, target in active_mounts:
            # Check if source device matches target or child partition (e.g. sda, sda1, nvme0n1p1)
            if dev_base in source:
                if target in FORBIDDEN_MOUNTS:
                    raise SafetyViolationError(
                        f"CRITICAL SAFETY ABORT: System partition '{source}' mounted at '{target}' "
                        f"belongs to device {device.path}. Cannot wipe active operating system disk."
                    )

    def _verify_unmounted(self, device: DeviceProfile) -> None:
        """Ensure all partitions on the device are fully unmounted."""
        if device.mountpoints:
            mps = ", ".join(device.mountpoints)
            raise SafetyViolationError(
                f"Device {device.path} has active mount points: [{mps}]. "
                f"All filesystems must be unmounted before sanitization."
            )

    @staticmethod
    def _get_live_system_mounts() -> list[tuple[str, str]]:
        """Parse active mounts from /proc/mounts if on Linux."""
        mounts: list[tuple[str, str]] = []
        proc_mounts = Path("/proc/mounts")
        if proc_mounts.exists():
            try:
                for line in proc_mounts.read_text(encoding="utf-8", errors="ignore").splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        mounts.append((parts[0], parts[1]))
            except Exception:
                pass
        return mounts

    @staticmethod
    def request_typed_confirmation(
        device: DeviceProfile,
        override_input: Optional[str] = None,
    ) -> bool:
        """Prompt operator to manually type the drive serial number to confirm.
        
        Args:
            device: Target device profile.
            override_input: Optional string for programmatic/test validation.
            
        Returns:
            True if confirmation string matches expected serial exactly.
            
        Raises:
            SafetyViolationError: If typed confirmation fails or is aborted.
        """
        expected = device.serial.strip()
        print("\n" + "=" * 70)
        print(" [!] DANGER: DESTRUCTIVE STORAGE SANITIZATION REQUESTED")
        print(f" Target Device:   {device.path}")
        print(f" Model:           {device.model}")
        print(f" Serial Number:   {expected}")
        print(f" Capacity:        {device.capacity_gb} GB ({device.size_bytes} bytes)")
        print(f" Media Type:      {device.media_type.value}")
        print(" ALL DATA ON THIS DEVICE WILL BE PERMANENTLY IRRECOVERABLE.")
        print("=" * 70)

        if override_input is not None:
            user_response = override_input.strip()
        else:
            prompt_msg = f"Type the exact serial number [{expected}] to confirm wipe: "
            try:
                user_response = input(prompt_msg).strip()
            except (KeyboardInterrupt, EOFError):
                raise SafetyViolationError("Wipe operation aborted by operator (interrupted).")

        if user_response != expected:
            raise SafetyViolationError(
                f"Confirmation failed: Expected serial '{expected}', but received '{user_response}'. "
                f"Aborting wipe operation to prevent data loss."
            )

        return True
