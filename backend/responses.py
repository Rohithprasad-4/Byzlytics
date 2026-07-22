"""Standardized JSON response envelope for all API endpoints."""

from __future__ import annotations

from typing import Any

from flask import jsonify


def api_response(
    *,
    status: str,
    message: str,
    data: Any = None,
    http_status: int = 200,
):
    """Return a consistent API envelope: {status, message, data}."""
    payload = {
        "status": status,
        "message": message,
        "data": data,
    }
    return jsonify(payload), http_status


def success_response(
    data: Any = None,
    message: str = "OK",
    http_status: int = 200,
):
    return api_response(
        status="success",
        message=message,
        data=data,
        http_status=http_status,
    )


def error_response(
    message: str,
    *,
    data: Any = None,
    http_status: int = 400,
):
    return api_response(
        status="error",
        message=message,
        data=data,
        http_status=http_status,
    )
