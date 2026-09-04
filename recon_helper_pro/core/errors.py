"""Exception hierarchy for Recon Helper Pro.

Every error a user can trigger has a plain-language ``message`` so the CLI can
show something useful without a traceback.
"""

from __future__ import annotations


class RHPError(Exception):
    """Base class for every Recon Helper Pro error."""


class ConfigError(RHPError):
    """Invalid or unusable configuration."""


class NotAuthorizedError(RHPError):
    """The authorization/ethics agreement has not been accepted yet."""


class ScopeError(RHPError):
    """A scope entry could not be parsed."""


class ScopeBlocked(RHPError):
    """A destination is hard-blocked and can never be contacted."""

    def __init__(self, message: str, *, target: str = "", reason: str = "") -> None:
        super().__init__(message)
        self.target = target
        self.reason = reason


class OutOfScope(RHPError):
    """A destination sits outside the engagement scope and was not overridden."""

    def __init__(self, message: str, *, target: str = "", reason: str = "") -> None:
        super().__init__(message)
        self.target = target
        self.reason = reason


class BudgetExceeded(RHPError):
    """A per-run, per-host or per-engagement request ceiling was reached."""


class Cancelled(RHPError):
    """The user cancelled the run (Ctrl-C or ``rhp cancel``)."""


class ModuleError(RHPError):
    """A recon module failed in a way it could not recover from."""


class TargetValidationError(RHPError):
    """A target string failed strict validation (see core.scope.validate_target)."""


class NetworkError(RHPError):
    """A network-level failure (DNS, TLS, connection, timeout)."""
