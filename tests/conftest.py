"""
Pytest configuration and test fixtures for WipeProof test suite.
Ensures all destructive tests execute strictly on temporary virtual sparse images.
"""

import os
import tempfile
from pathlib import Path
from typing import Generator
import pytest

from wipeproof.core.models import DeviceProfile, MediaType


@pytest.fixture
def temp_sparse_image() -> Generator[Path, None, None]:
    """Creates a temporary 2MB virtual disk image populated with random data."""
    with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as f:
        path = Path(f.name)
        # Write 2 MB of random bytes to simulate an active customer drive with data
        random_bytes = os.urandom(1024 * 1024 * 2)
        f.write(random_bytes)
        f.flush()

    try:
        yield path
    finally:
        if path.exists():
            try:
                path.unlink()
            except OSError:
                pass


@pytest.fixture
def mock_device_profile(temp_sparse_image: Path) -> DeviceProfile:
    """Fixture returning a valid virtual loopback DeviceProfile."""
    return DeviceProfile(
        path=str(temp_sparse_image),
        model="Test Virtual Sparse Drive",
        serial="SN-TEST-LOOP-001",
        size_bytes=temp_sparse_image.stat().st_size,
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
