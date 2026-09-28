"""
WipeProof HPA/DCO Auditor & Unhider.

Audits Host Protected Area (HPA) and Device Configuration Overlay (DCO)
on ATA storage devices using hdparm, restores full physical capacity,
and logs native max sectors before and after.
"""

from __future__ import annotations
import re
import shutil
import subprocess
from typing import Optional

from wipeproof.core.models import HpaDcoState


class HpaDcoAuditor:
    """Manages detection, reporting, and restoration of HPA and DCO."""

    def __init__(self, hdparm_path: Optional[str] = None):
        self.hdparm_bin = hdparm_path or shutil.which("hdparm")

    def audit_and_unhide(
        self,
        device_path: str,
        is_ata: bool = True,
        simulate_hpa_sectors: Optional[tuple[int, int]] = None,
    ) -> HpaDcoState:
        """Audit and restore HPA/DCO.
        
        Args:
            device_path: Target block device node.
            is_ata: Whether device is an ATA/SATA drive (HPA/DCO is an ATA feature).
            simulate_hpa_sectors: (visible_sectors, native_max_sectors) tuple for unit testing.
            
        Returns:
            HpaDcoState record with sectors before/after.
        """
        # Handle unit test simulation
        if simulate_hpa_sectors:
            vis, nat = simulate_hpa_sectors
            hpa_detected = nat > vis
            return HpaDcoState(
                hpa_detected=hpa_detected,
                dco_detected=False,
                native_max_sectors_before=vis,
                native_max_sectors_after=nat,
                hpa_removed=hpa_detected,
                dco_restored=False,
                details=f"Simulated HPA: unhidden {nat - vis} hidden sectors." if hpa_detected else "No HPA detected.",
            )

        # HPA and DCO are specific to ATA/SATA. For NVMe, USB, or loopback, record N/A
        if not is_ata or not self.hdparm_bin:
            return HpaDcoState(
                hpa_detected=False,
                dco_detected=False,
                native_max_sectors_before=0,
                native_max_sectors_after=0,
                hpa_removed=False,
                dco_restored=False,
                details="HPA/DCO audit not applicable to non-ATA media or hdparm not present.",
            )

        state = HpaDcoState()

        # Step 1: Query HPA Native Max Sectors Before
        vis_before, nat_before = self._query_max_sectors(device_path)
        state.native_max_sectors_before = vis_before

        if nat_before > vis_before:
            state.hpa_detected = True
            # Step 2: Unhide HPA by setting max sectors to native max (permanent)
            success = self._set_max_sectors(device_path, nat_before)
            state.hpa_removed = success

        # Step 3: Check DCO capabilities
        dco_present = self._query_dco(device_path)
        if dco_present:
            state.dco_detected = True
            dco_success = self._restore_dco(device_path)
            state.dco_restored = dco_success

        # Step 4: Re-query Native Max Sectors After
        vis_after, _ = self._query_max_sectors(device_path)
        state.native_max_sectors_after = vis_after

        state.details = (
            f"HPA: {'Removed' if state.hpa_removed else ('Detected' if state.hpa_detected else 'None')}; "
            f"DCO: {'Restored' if state.dco_restored else ('Detected' if state.dco_detected else 'None')}; "
            f"Sectors Before: {vis_before}, Sectors After: {vis_after}"
        )
        return state

    def _query_max_sectors(self, device_path: str) -> tuple[int, int]:
        """Run `hdparm -N` and parse (visible_sectors, native_max_sectors)."""
        if not self.hdparm_bin:
            return 0, 0

        cmd = [self.hdparm_bin, "-N", device_path]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            output = res.stdout

            # Match patterns like: "max sectors = 1953525168/1953525168, HPA is disabled"
            # or: "max sectors = 1000000/2000000, HPA is enabled"
            match = re.search(r"max sectors\s*=\s*(\d+)/(\d+)", output)
            if match:
                visible = int(match.group(1))
                native = int(match.group(2))
                return visible, native

            match_single = re.search(r"max sectors\s*=\s*(\d+)", output)
            if match_single:
                s = int(match_single.group(1))
                return s, s
        except Exception:
            pass

        return 0, 0

    def _set_max_sectors(self, device_path: str, target_sectors: int) -> bool:
        """Unhide HPA sectors using `hdparm -N p<target_sectors>`."""
        if not self.hdparm_bin:
            return False

        cmd = [self.hdparm_bin, f"-Np{target_sectors}", device_path]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            return res.returncode == 0
        except Exception:
            return False

    def _query_dco(self, device_path: str) -> bool:
        """Inspect DCO status using `hdparm --dco-identify`."""
        if not self.hdparm_bin:
            return False

        cmd = [self.hdparm_bin, "--dco-identify", device_path]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            # DCO identify lists feature sets or Real max sectors
            return "Real max sectors" in res.stdout or "DCO" in res.stdout
        except Exception:
            return False

    def _restore_dco(self, device_path: str) -> bool:
        """Restore DCO settings using `hdparm --yes-i-know-what-i-am-doing --dco-restore`."""
        if not self.hdparm_bin:
            return False

        cmd = [self.hdparm_bin, "--yes-i-know-what-i-am-doing", "--dco-restore", device_path]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            return res.returncode == 0
        except Exception:
            return False
