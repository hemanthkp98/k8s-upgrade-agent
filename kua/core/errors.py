"""Exception hierarchy for kua."""


class KuaError(Exception):
    """Base exception for all errors in kua."""


class ConfigError(KuaError):
    """Raised when configuration loading or validation fails."""
