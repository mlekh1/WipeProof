"""
Tests for Shannon Entropy and PostWipeVerifier calculations.
"""

import os
from wipeproof.core.verifier import PostWipeVerifier


def test_shannon_entropy_all_zeros():
    """All zeros should yield exactly 0.0 entropy."""
    zeros = b"\x00" * 8192
    entropy = PostWipeVerifier.calculate_entropy(zeros)
    assert entropy == 0.0


def test_shannon_entropy_all_single_byte():
    """Buffer with identical repeated bytes (e.g. all 0xFF) has 0.0 entropy."""
    ffs = b"\xff" * 8192
    entropy = PostWipeVerifier.calculate_entropy(ffs)
    assert entropy == 0.0


def test_shannon_entropy_random_bytes():
    """Cryptographically random bytes should yield close to 8.0 bits/byte entropy."""
    rand = os.urandom(65536)
    entropy = PostWipeVerifier.calculate_entropy(rand)
    # Uniform random 8-bit bytes should have entropy > 7.95
    assert entropy >= 7.95


def test_shannon_entropy_mixed_pattern():
    """Half zeros, half ones should have entropy of exactly 1.0 bit/byte."""
    mixed = (b"\x00" * 4096) + (b"\x01" * 4096)
    entropy = PostWipeVerifier.calculate_entropy(mixed)
    assert abs(entropy - 1.0) < 0.001
