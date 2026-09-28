"""
WipeProof Device Discovery Subsystem.

Discovers storage devices, media classification (HDD vs SATA SSD vs NVMe vs USB),
hardware identifiers (vendor, model, serial, WWN, firmware), sector sizes,
encryption status (LUKS, BitLocker), and active mountpoints.
"""

from __future__ import annotations
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional

from wipeproof.core.exceptions import DeviceNotFoundError
from wipeproof.core.models import DeviceProfile, MediaType


class DeviceDiscovery:
    """Discovers and inspects physical and virtual storage devices."""

    def __init__(self, sys_block_dir: Path = Path("/sys/block")):
        self.sys_block_dir = sys_block_dir

    def get_device_profile(self, path: str) -> DeviceProfile:
        """Inspect and return the full profile for a specific device path.
        
        Args:
            path: Device path, e.g. '/dev/sda', '/dev/nvme0n1', '/dev/loop0', or virtual image file.
            
        Raises:
            DeviceNotFoundError: If device does not exist.
        """
        # Handle virtual sparse image file directly (for safe testing)
        if os.path.isfile(path) or path.endswith((".img", ".raw")):
            return self._profile_virtual_file(path)

        # On Linux, verify block special device exists
        if not os.path.exists(path):
            raise DeviceNotFoundError(f"Storage device node '{path}' not found.")

        # If lsblk is available (standard on Linux), query detailed JSON topology
        if shutil.which("lsblk"):
            profile = self._profile_via_lsblk(path)
            if profile:
                return profile

        # Fallback to direct /sys/block and sysfs inspection
        return self._profile_via_sysfs(path)

    def _profile_virtual_file(self, file_path: str) -> DeviceProfile:
        """Create profile for a virtual image file used in testing/simulation."""
        p = Path(file_path).resolve()
        size_bytes = p.stat().st_size if p.exists() else 0
        name = p.stem

        return DeviceProfile(
            path=str(p),
            model=f"Virtual Sparse Disk ({name})",
            serial=f"SIM-{abs(hash(str(p))) % 1000000000:09d}",
            size_bytes=size_bytes,
            media_type=MediaType.VIRTUAL_LOOPBACK,
            sector_size_logical=512,
            sector_size_physical=512,
            bus_type="virtual",
            is_rotational=False,
            is_removable=False,
            is_read_only=False,
            is_encrypted=False,
            mountpoints=[],
        )

    def _profile_via_lsblk(self, path: str) -> Optional[DeviceProfile]:
        """Query device details via lsblk in JSON format."""
        cmd = [
            "lsblk",
            "-J",
            "-b",
            "-O",
            path,
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode != 0 or not res.stdout.strip():
                return None

            data = json.loads(res.stdout)
            devices = data.get("blockdevices", [])
            if not devices:
                return None

            dev = devices[0]
            dev_name = dev.get("name", "")
            tran = (dev.get("tran") or "").lower()
            subsystems = (dev.get("subsystems") or "").lower()
            rota = dev.get("rota", False)
            rm = dev.get("rm", False)
            ro = dev.get("ro", False)
            size_bytes = int(dev.get("size") or 0)
            phy_sec = int(dev.get("phy-sec") or 512)
            log_sec = int(dev.get("log-sec") or 512)
            model = (dev.get("model") or "Generic Storage Device").strip()
            serial = (dev.get("serial") or f"SN-UNKNOWN-{dev_name}").strip()
            wwn = dev.get("wwn")
            rev = dev.get("rev")
            fstype = (dev.get("fstype") or "").lower()

            # Collect all mountpoints recursively from device and partitions
            mountpoints: list[str] = []
            self._collect_mountpoints(dev, mountpoints)

            # Check for encryption
            is_encrypted = "crypto_luks" in fstype or "bitlocker" in fstype
            enc_type = "LUKS" if "crypto_luks" in fstype else ("BitLocker" if "bitlocker" in fstype else None)

            # Classify media type
            media_type = self._classify_media_type(
                path=path,
                tran=tran,
                is_rotational=rota,
                is_removable=rm,
                subsystems=subsystems,
            )

            return DeviceProfile(
                path=path,
                model=model,
                serial=serial,
                size_bytes=size_bytes,
                media_type=media_type,
                sector_size_logical=log_sec,
                sector_size_physical=phy_sec,
                wwn=wwn,
                firmware_revision=rev,
                bus_type=tran or ("virtual" if media_type == MediaType.VIRTUAL_LOOPBACK else "unknown"),
                is_rotational=bool(rota),
                is_removable=bool(rm),
                is_read_only=bool(ro),
                is_encrypted=is_encrypted,
                encryption_type=enc_type,
                mountpoints=mountpoints,
            )
        except Exception:
            return None

    def _profile_via_sysfs(self, path: str) -> DeviceProfile:
        """Fallback device profiling using /sys/block."""
        dev_name = os.path.basename(path)
        sys_dev = self.sys_block_dir / dev_name

        size_bytes = 0
        is_rotational = False
        is_ro = False
        is_rm = False
        model = "Unknown Storage Device"
        serial = f"SN-SYSFS-{dev_name}"

        if sys_dev.exists():
            # Size in 512-byte sectors
            size_file = sys_dev / "size"
            if size_file.exists():
                try:
                    size_bytes = int(size_file.read_text().strip()) * 512
                except ValueError:
                    pass

            # Rotational flag
            rota_file = sys_dev / "queue" / "rotational"
            if rota_file.exists():
                try:
                    is_rotational = rota_file.read_text().strip() == "1"
                except Exception:
                    pass

            # Read-only flag
            ro_file = sys_dev / "ro"
            if ro_file.exists():
                try:
                    is_ro = ro_file.read_text().strip() == "1"
                except Exception:
                    pass

            # Removable flag
            rm_file = sys_dev / "removable"
            if rm_file.exists():
                try:
                    is_rm = rm_file.read_text().strip() == "1"
                except Exception:
                    pass

            # Device model
            model_file = sys_dev / "device" / "model"
            if model_file.exists():
                try:
                    model = model_file.read_text().strip()
                except Exception:
                    pass

            # Device serial
            serial_file = sys_dev / "device" / "serial"
            if serial_file.exists():
                try:
                    serial = serial_file.read_text().strip()
                except Exception:
                    pass

        media_type = self._classify_media_type(
            path=path,
            tran="nvme" if "nvme" in dev_name else "ata",
            is_rotational=is_rotational,
            is_removable=is_rm,
            subsystems="",
        )

        return DeviceProfile(
            path=path,
            model=model,
            serial=serial,
            size_bytes=size_bytes,
            media_type=media_type,
            sector_size_logical=512,
            sector_size_physical=512,
            bus_type="nvme" if media_type == MediaType.NVME_SSD else "ata",
            is_rotational=is_rotational,
            is_removable=is_rm,
            is_read_only=is_ro,
            is_encrypted=False,
            mountpoints=[],
        )

    def _collect_mountpoints(self, node: dict[str, Any], results: list[str]) -> None:
        """Recursively collect mountpoints from block device hierarchy."""
        mp = node.get("mountpoint") or node.get("mountpoints")
        if isinstance(mp, list):
            for m in mp:
                if m and m not in results:
                    results.append(m)
        elif isinstance(mp, str) and mp.strip():
            if mp not in results:
                results.append(mp)

        for child in node.get("children", []):
            self._collect_mountpoints(child, results)

    @staticmethod
    def _classify_media_type(
        path: str,
        tran: str,
        is_rotational: bool,
        is_removable: bool,
        subsystems: str,
    ) -> MediaType:
        """Classify storage media based on bus transport, rotational bit, and path."""
        p_lower = path.lower()
        if "loop" in p_lower or p_lower.endswith((".img", ".raw")):
            return MediaType.VIRTUAL_LOOPBACK
        if "nvme" in p_lower or tran == "nvme":
            return MediaType.NVME_SSD
        if tran == "usb" or is_removable:
            return MediaType.USB_REMOVABLE
        if is_rotational:
            return MediaType.ROTATIONAL_HDD
        return MediaType.SATA_SSD
