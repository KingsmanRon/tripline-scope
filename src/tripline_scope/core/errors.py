class TriplineError(Exception):
    """Base error. Messages must never contain patient data, secret values or connection strings."""

    exit_code = 1


class ConfigError(TriplineError):
    exit_code = 2


class PermissionDenied(TriplineError):
    exit_code = 3


class AuthenticationFailed(PermissionDenied):
    pass


class IntegrityError(TriplineError):
    exit_code = 4


class SourceModified(IntegrityError):
    pass


class LegalHoldActive(TriplineError):
    exit_code = 5


class CaseClosed(TriplineError):
    exit_code = 6


class NotReady(TriplineError):
    exit_code = 7
