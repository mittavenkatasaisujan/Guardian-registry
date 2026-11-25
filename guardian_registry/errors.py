class RegistryError(Exception):
    status = 400
    code: str | None = None   # a stable name apps can check; the message itself is translated


class NotFound(RegistryError):
    status = 404


class Forbidden(RegistryError):
    status = 403


class Conflict(RegistryError):
    status = 409


class Invalid(RegistryError):
    status = 422


class NotEnrolled(Invalid):
    """Sign-in for a number with no account: the app should ask for a name to create one."""
    code = "not_enrolled"


class AdultRequired(Invalid):
    """A new account needs the person to confirm they are 18 or older (the service is for adults)."""
    code = "adult_required"


class Unauthorized(RegistryError):
    status = 401


class TooMany(RegistryError):
    status = 429
