"""Custom API exceptions with HTTP status mapping."""

from __future__ import annotations


class APIError(Exception):
    """Base exception for predictable API failures."""

    status_code: int = 500
    message: str = "Internal server error"

    def __init__(self, message: str | None = None, *, data: dict | list | None = None):
        self.message = message or self.__class__.message
        self.data = data
        super().__init__(self.message)


class ValidationError(APIError):
    status_code = 400
    message = "Validation failed"


class NotFoundError(APIError):
    status_code = 404
    message = "Resource not found"


class ConflictError(APIError):
    status_code = 409
    message = "Resource conflict"


class DatabaseError(APIError):
    status_code = 503
    message = "Database operation failed"


class ServiceUnavailableError(APIError):
    status_code = 503
    message = "Service temporarily unavailable"
