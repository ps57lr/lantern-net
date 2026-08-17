"""Safe rendering for untrusted text written to a human terminal."""

from __future__ import annotations

import unicodedata


def terminal_safe(value: object, *, max_chars: int = 4096) -> str:
    """Render terminal controls, line breaks, and bidi controls as visible text."""

    if not isinstance(max_chars, int) or isinstance(max_chars, bool) or max_chars < 1:
        raise ValueError("max_chars must be a positive integer")
    source = str(value)
    truncated = len(source) > max_chars
    if truncated:
        source = source[:max_chars]
    rendered = "".join(_safe_character(character) for character in source)
    return rendered + ("…" if truncated else "")


def _safe_character(character: str) -> str:
    codepoint = ord(character)
    if unicodedata.category(character) not in {"Cc", "Cf", "Cs"}:
        return character
    common = {
        "\n": r"\n",
        "\r": r"\r",
        "\t": r"\t",
        "\b": r"\b",
        "\f": r"\f",
        "\x1b": r"\x1b",
        "\x07": r"\x07",
    }
    if character in common:
        return common[character]
    if codepoint <= 0xFF:
        return f"\\x{codepoint:02x}"
    if codepoint <= 0xFFFF:
        return f"\\u{codepoint:04x}"
    return f"\\U{codepoint:08x}"
