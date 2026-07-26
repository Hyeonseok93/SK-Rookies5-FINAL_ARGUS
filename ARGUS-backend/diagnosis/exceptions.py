"""Shared diagnosis runtime exceptions."""


class DiagnosisCancelled(Exception):
    """Raised when the user requests cancellation mid-run."""
