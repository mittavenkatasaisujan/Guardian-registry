class RegistryError(Exception):
    status = 400


class NotFound(RegistryError):
    status = 404


class Forbidden(RegistryError):
    status = 403


class Conflict(RegistryError):
    status = 409


class Invalid(RegistryError):
    status = 422


class Unauthorized(RegistryError):
    status = 401


class TooMany(RegistryError):
    status = 429
