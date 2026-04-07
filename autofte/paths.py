"""Shared path defaults used by more than one subcommand.

Kept in one place so the "where are the crash files" guess only lives
once instead of being copy-pasted across the CLI and shell scripts.
"""

from pathlib import Path

DEFAULT_CRASH_DIRS = (
    "out/default/crashes",
    "out/crashes",
    "crashes",
)


def pick_crash_dir(candidates=DEFAULT_CRASH_DIRS):
    """Return the first candidate crash directory that exists on disk.

    Falls back to the first candidate (even if missing) so callers always
    get a path they can report back to the user in an error message.
    """
    for candidate in candidates:
        if Path(candidate).exists():
            return candidate
    return candidates[0]
