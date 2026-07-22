"""Flask route definitions for SecureGate AI REST API.

Endpoint surface follows Appendix A of the project report. Response
envelope for every route: {status, message, data}.
"""

from __future__ import annotations

from io import BytesIO

from flask import Blueprint, current_app, request, send_file

from backend import models, services
from backend.exceptions import APIError, NotFoundError
from backend.responses import error_response, success_response
from backend.serializers import (
    serialize_daily_summary,
    serialize_decision,
    serialize_device,
    serialize_event,
    serialize_pagination,
    serialize_risk,
    serialize_stats,
    serialize_top_risky_device,
)
from backend.validators import (
    validate_allow_block_payload,
    validate_assess_batch_payload,
    validate_assess_payload,
    validate_days_param,
    validate_decide_payload,
    validate_ip_address,
    validate_limit_param,
    validate_optional_protocol,
    validate_optional_risk_category,
    validate_pagination,
    validate_report_date,
    validate_uuid,
)
from reports.report_builder import generate_report, list_generated_reports

api_bp = Blueprint("api", __name__)


def _get_query_args() -> dict:
    return {k: v for k, v in request.args.items()}


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@api_bp.route("/health", methods=["GET"])
def health():
    from datetime import datetime, timezone

    from backend.database import check_health

    db_health = check_health()
    status = "healthy" if db_health.get("database") == "connected" else "degraded"
    http_status = 200 if status == "healthy" else 503

    return success_response(
        data={
            "backend": "online",
            "service": "SecureGate AI",
            "status": status,
            "database": db_health,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "1.0.0",
        },
        message="Health check complete.",
        http_status=http_status,
    )


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------

@api_bp.route("/devices", methods=["GET"])
def get_devices():
    pagination = validate_pagination(_get_query_args())
    ip_filter = _get_query_args().get("ip_address")
    if ip_filter:
        ip_filter = validate_ip_address(ip_filter)

    rows = models.list_devices(
        limit=pagination["limit"],
        offset=pagination["offset"],
        ip_address=ip_filter,
    )
    total = models.count_devices()
    items = [serialize_device(row) for row in rows]

    return success_response(
        data=serialize_pagination(items, page=pagination["page"], limit=pagination["limit"], total=total),
        message="Devices retrieved successfully.",
    )


@api_bp.route("/devices/stats", methods=["GET"])
def get_devices_stats():
    stats = models.get_device_stats()
    return success_response(data=stats, message="Device statistics retrieved successfully.")


@api_bp.route("/devices/lookup/<ip_address>", methods=["GET"])
def get_device_by_ip_route(ip_address: str):
    ip_address = validate_ip_address(ip_address)
    row = models.get_device_by_ip(ip_address)
    if row is None:
        raise NotFoundError(f"No device found for {ip_address}.")
    return success_response(data=serialize_device(row), message="Device retrieved successfully.")


@api_bp.route("/devices/<device_id>", methods=["GET"])
def get_device(device_id: str):
    device_id = validate_uuid(device_id)
    row = models.get_device_by_id(device_id)
    if row is None:
        raise NotFoundError(f"Device {device_id} not found.")
    return success_response(data=serialize_device(row), message="Device retrieved successfully.")


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

@api_bp.route("/events", methods=["GET"])
def get_events():
    args = _get_query_args()
    pagination = validate_pagination(args)
    protocol = validate_optional_protocol(args.get("protocol"))
    source_ip = args.get("source_ip")
    if source_ip:
        source_ip = validate_ip_address(source_ip, "source_ip")

    rows = models.list_events(
        limit=pagination["limit"],
        offset=pagination["offset"],
        protocol=protocol,
        source_ip=source_ip,
    )
    total = models.count_events(protocol=protocol)
    items = [serialize_event(row) for row in rows]

    return success_response(
        data=serialize_pagination(items, page=pagination["page"], limit=pagination["limit"], total=total),
        message="Events retrieved successfully.",
    )


@api_bp.route("/events/protocols", methods=["GET"])
def get_events_by_protocol():
    rows = models.get_events_by_protocol()
    return success_response(data=rows, message="Protocol distribution retrieved successfully.")


@api_bp.route("/events/hourly", methods=["GET"])
def get_events_hourly():
    rows = models.get_events_hourly_today()
    return success_response(data=rows, message="Hourly event distribution retrieved successfully.")


@api_bp.route("/events/<int:event_id>", methods=["GET"])
def get_event(event_id: int):
    row = models.get_event_by_id(event_id)
    if row is None:
        raise NotFoundError(f"Event {event_id} not found.")
    return success_response(data=serialize_event(row), message="Event retrieved successfully.")


# ---------------------------------------------------------------------------
# Risks
# ---------------------------------------------------------------------------

@api_bp.route("/risks", methods=["GET"])
def get_risks():
    args = _get_query_args()
    pagination = validate_pagination(args)
    risk_category = validate_optional_risk_category(args.get("risk_category"))

    min_score = args.get("min_score")
    min_score_val = float(min_score) if min_score is not None else None

    rows = models.list_risks(
        limit=pagination["limit"],
        offset=pagination["offset"],
        risk_category=risk_category,
        min_score=min_score_val,
    )
    total = models.count_risks(risk_category=risk_category)
    items = [serialize_risk(row) for row in rows]

    return success_response(
        data=serialize_pagination(items, page=pagination["page"], limit=pagination["limit"], total=total),
        message="Risk assessments retrieved successfully.",
    )


@api_bp.route("/risks/top", methods=["GET"])
def get_top_risks():
    limit = validate_limit_param(_get_query_args().get("limit"), default=10, maximum=100)
    rows = models.get_top_risky_devices(limit=limit)
    return success_response(
        data=[serialize_top_risky_device(r) for r in rows],
        message="Top risky devices retrieved successfully.",
    )


# ---------------------------------------------------------------------------
# Dashboard aggregate stats
# ---------------------------------------------------------------------------

@api_bp.route("/stats", methods=["GET"])
def get_stats():
    stats = models.build_stats_payload()
    return success_response(
        data=serialize_stats(stats),
        message="Statistics retrieved successfully.",
    )


@api_bp.route("/summary", methods=["GET"])
def get_summary():
    days = validate_days_param(_get_query_args().get("days"), default=7, maximum=90)
    rows = models.list_daily_summaries(days=days)
    return success_response(
        data=[serialize_daily_summary(r) for r in rows],
        message="Daily summaries retrieved successfully.",
    )


@api_bp.route("/summary/generate", methods=["POST"])
def generate_summary():
    payload = request.get_json(silent=True) or {}
    summary_date = validate_report_date(payload.get("date"))
    row = models.generate_daily_summary(summary_date)
    return success_response(
        data=serialize_daily_summary(row),
        message="Daily summary generated successfully.",
        http_status=201,
    )


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------

@api_bp.route("/decisions", methods=["GET"])
def get_decisions():
    args = _get_query_args()
    pagination = validate_pagination(args)
    active_only = args.get("active_only", "true").lower() != "false"

    rows = models.list_decisions(
        limit=pagination["limit"],
        offset=pagination["offset"],
        active_only=active_only,
    )
    total = models.count_decisions(active_only=active_only)
    items = [serialize_decision(row) for row in rows]

    return success_response(
        data=serialize_pagination(items, page=pagination["page"], limit=pagination["limit"], total=total),
        message="Decisions retrieved successfully.",
    )


@api_bp.route("/decisions/history", methods=["GET"])
def get_decisions_history():
    args = _get_query_args()
    ip_filter = args.get("ip")
    if ip_filter:
        ip_filter = validate_ip_address(ip_filter, "ip")
    limit = validate_limit_param(args.get("limit"), default=50, maximum=500)
    rows = models.get_decision_history(ip_address=ip_filter, limit=limit)
    return success_response(
        data=[serialize_decision(r) for r in rows],
        message="Decision history retrieved successfully.",
    )


@api_bp.route("/decisions/summary", methods=["GET"])
def get_decisions_summary():
    summary = models.get_decision_summary()
    return success_response(data=summary, message="Decision summary retrieved successfully.")


@api_bp.route("/decisions/active/<ip_address>", methods=["GET"])
def get_active_decision(ip_address: str):
    ip_address = validate_ip_address(ip_address)
    row = models.get_active_decision_for_ip(ip_address)
    return success_response(
        data=serialize_decision(row) if row else None,
        message="Active decision retrieved successfully.",
    )


@api_bp.route("/decide", methods=["POST"])
def decide():
    payload = validate_decide_payload(request.get_json(silent=True))
    result = services.apply_decision(
        ip_address=payload["ip_address"],
        action=payload["action"],
        device_id=payload.get("device_id"),
        reason=payload.get("reason"),
        assessment_id=payload.get("assessment_id"),
        triggered_by="decide_endpoint",
    )
    return success_response(
        data={
            "decision": serialize_decision(result["decision"]),
            "device": serialize_device(result["device"]),
        },
        message="Decision recorded successfully.",
        http_status=201,
    )


@api_bp.route("/allow", methods=["POST"])
def allow():
    payload = validate_allow_block_payload(request.get_json(silent=True))
    result = services.allow_device(
        ip_address=payload.get("ip_address"),
        device_id=payload.get("device_id"),
        reason=payload.get("reason"),
        permanent=payload.get("permanent", False),
    )
    return success_response(
        data={
            "decision": serialize_decision(result["decision"]),
            "device": serialize_device(result["device"]),
        },
        message="Device allowed successfully.",
        http_status=201,
    )


@api_bp.route("/block", methods=["POST"])
def block():
    payload = validate_allow_block_payload(request.get_json(silent=True))
    result = services.block_device(
        ip_address=payload.get("ip_address"),
        device_id=payload.get("device_id"),
        reason=payload.get("reason"),
        permanent=payload.get("permanent", False),
    )
    return success_response(
        data={
            "decision": serialize_decision(result["decision"]),
            "device": serialize_device(result["device"]),
        },
        message="Device blocked successfully.",
        http_status=201,
    )


@api_bp.route("/revoke/<ip_address>", methods=["POST"])
def revoke(ip_address: str):
    ip_address = validate_ip_address(ip_address)
    device = services.revoke_decisions_for_ip(ip_address)
    return success_response(
        data={"ip_address": ip_address, "device": serialize_device(device)},
        message=f"All decisions revoked for {ip_address}.",
    )


@api_bp.route("/check/<ip_address>", methods=["GET"])
def check_ip(ip_address: str):
    ip_address = validate_ip_address(ip_address)
    return success_response(
        data={"ip_address": ip_address, "is_blocked": models.is_ip_blocked(ip_address)},
        message="Block status retrieved successfully.",
    )


@api_bp.route("/permitted/<ip_address>", methods=["GET"])
def permitted(ip_address: str):
    ip_address = validate_ip_address(ip_address)
    result = services.get_permitted_status(ip_address)
    return success_response(
        data={
            "ip_address": ip_address,
            "is_permitted": result["is_permitted"],
            "decision": serialize_decision(result["decision"]) if result["decision"] else None,
        },
        message="Permission status retrieved successfully.",
    )


# ---------------------------------------------------------------------------
# Assessment (ML + AI risk engine)
# ---------------------------------------------------------------------------

@api_bp.route("/assess", methods=["POST"])
def assess():
    """Backward-compatible single-event assessment (event_id), or a bulk
    run when the payload explicitly requests one (event_ids/use_gpt)."""
    body = request.get_json(silent=True) or {}

    if "event_id" in body:
        payload = validate_assess_payload(body)
        result = services.assess_event(
            event_id=payload["event_id"],
            force_reassess=payload["force_reassess"],
        )
        message = (
            "Risk assessment created successfully."
            if result["created"]
            else "Existing risk assessment returned."
        )
        status_code = 201 if result["created"] else 200
        return success_response(
            data={
                "assessment": serialize_risk({**result["assessment"]}),
                "created": result["created"],
            },
            message=message,
            http_status=status_code,
        )

    if "event_ids" in body or "use_gpt" in body:
        payload = validate_assess_batch_payload(body)
        results = services.run_bulk_assessment(
            event_ids=payload["event_ids"],
            limit=payload["limit"],
            use_gpt=payload["use_gpt"],
        )
        return success_response(
            data={"assessed": len(results), "results": results},
            message=f"Assessment pipeline processed {len(results)} event(s).",
            http_status=201 if results else 200,
        )

    # No event_id and no explicit bulk signal: fall through to the
    # single-event validator so the familiar "event_id is required." error
    # is raised for empty/ambiguous payloads.
    validate_assess_payload(body)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

@api_bp.route("/report/list", methods=["GET"])
def list_reports():
    reports = list_generated_reports(current_app.config["REPORTS_DIR"])
    return success_response(data=reports, message="Generated reports listed successfully.")


@api_bp.route("/report/generate", methods=["POST"])
def generate_report_route():
    payload = request.get_json(silent=True) or {}
    report_date = validate_report_date(payload.get("date"))
    _, filename = generate_report(
        report_date=report_date,
        output_dir=current_app.config["REPORTS_DIR"],
    )
    return success_response(
        data={"file_path": f"{current_app.config['REPORTS_DIR']}/{filename}", "filename": filename},
        message="Report generated successfully.",
        http_status=201,
    )


@api_bp.route("/report/download", methods=["GET"])
def download_report():
    report_date = validate_report_date(_get_query_args().get("date"))
    pdf_bytes, filename = generate_report(
        report_date=report_date,
        output_dir=current_app.config["REPORTS_DIR"],
    )
    return send_file(
        BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


@api_bp.app_errorhandler(APIError)
def handle_api_error(error: APIError):
    return error_response(error.message, data=error.data, http_status=error.status_code)
