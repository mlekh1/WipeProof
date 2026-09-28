"""
WipeProof RFC 8785 JSON Canonicalization Scheme (JCS) Implementation.

RFC 8785 defines a deterministic, language-independent byte serialization for JSON:
1. Lexicographical UTF-16 code unit sorting of object keys.
2. Removal of all insignificant whitespace.
3. Strict ECMAScript / IEEE-754 number formatting (e.g. -0 -> 0).
4. Strict string escaping (only quote, backslash, and U+0000..U+001F).
5. Raw UTF-8 byte emission for all other Unicode code points.
"""

from __future__ import annotations
import math
from typing import Any


def canonicalize_jcs(obj: Any) -> bytes:
    """Canonicalize a Python object (dict, list, primitive) to RFC 8785 canonical UTF-8 bytes.
    
    Args:
        obj: JSON-serializable Python data structure.
        
    Returns:
        Deterministic bytes sequence according to RFC 8785.
    """
    return _serialize(obj).encode("utf-8")


def _serialize(obj: Any) -> str:
    """Recursive serializer adhering to RFC 8785 rules."""
    if obj is None:
        return "null"

    if isinstance(obj, bool):
        return "true" if obj else "false"

    if isinstance(obj, (int, float)):
        return _format_number(obj)

    if isinstance(obj, str):
        return _escape_string(obj)

    if isinstance(obj, list):
        return "[" + ",".join(_serialize(item) for item in obj) + "]"

    if isinstance(obj, dict):
        # RFC 8785 Section 3.2.2: Sort keys by UTF-16 code units
        sorted_keys = sorted(obj.keys(), key=lambda k: k.encode("utf-16be"))
        items = [f"{_escape_string(k)}:{_serialize(obj[k])}" for k in sorted_keys]
        return "{" + ",".join(items) + "}"

    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable according to RFC 8785")


def _format_number(val: int | float) -> str:
    """Format integers and floats according to RFC 8785 / ECMAScript specifications."""
    if isinstance(val, int) and not isinstance(val, bool):
        return str(val)

    # Float handling
    if math.isnan(val) or math.isinf(val):
        raise ValueError("NaN and Infinity are not valid JSON numbers")

    # Negative zero handling: -0.0 -> 0
    if val == 0.0:
        return "0"

    # In ECMAScript, if float has no fractional part, serialize as integer
    if val.is_integer() and abs(val) < 1e21:
        return str(int(val))

    # Python float to string standard format
    s = str(val)

    # Normalize scientific notation e+05 -> e+5 or e5 per ECMAScript rules
    if "e" in s:
        mantissa, exp = s.split("e")
        exp_int = int(exp)
        # ECMAScript exponent formatting: e+21 -> e21, e-5 -> e-5
        if exp_int >= 0:
            return f"{mantissa}e+{exp_int}".replace("e+", "e")
        return f"{mantissa}e{exp_int}"

    return s


def _escape_string(s: str) -> str:
    """Escape string according to RFC 8785 Section 3.2.4.
    
    Only quotation mark (0x22), reverse solidus (0x5C), and control characters
    (0x00 to 0x1F) are escaped. Forward slash (/) MUST NOT be escaped.
    """
    out: list[str] = ['"']
    for char in s:
        code = ord(char)
        if char == '"':
            out.append('\\"')
        elif char == '\\':
            out.append('\\\\')
        elif char == '\b':
            out.append('\\b')
        elif char == '\f':
            out.append('\\f')
        elif char == '\n':
            out.append('\\n')
        elif char == '\r':
            out.append('\\r')
        elif char == '\t':
            out.append('\\t')
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            # Emit raw character (UTF-8)
            out.append(char)
    out.append('"')
    return "".join(out)
