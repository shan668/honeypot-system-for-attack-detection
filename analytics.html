"""Flask application factory for the AegisTrap dashboard."""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any, Callable

from flask import Flask, Response, jsonify, render_template, request

from aegistrap import __version__
from aegistrap.utils.probe_analysis import analyze_command, analyze_credential


def create_dashboard_app(
    *,
    config: Any,
    database: Any,
    analytics: Any,
    session_manager: Any,
    threat_engine: Any,
    logger: Any,
    listeners: dict[str, Any] | None = None,
) -> Flask:
    """Create the dashboard and API endpoints used by the templates."""
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = config.dashboard.secret_key
    listeners = listeners or {}

    @app.context_processor
    def inject_globals() -> dict[str, Any]:
        return {
            "project_name": config.general.get("project_name", "AegisTrap"),
            "version": config.general.get("version", __version__),
            "refresh_interval_ms": int(config.dashboard.refresh_interval_ms),
        }

    @app.errorhandler(404)
    def not_found(_: Exception) -> tuple[str, int]:
        return render_template("dashboard/404.html"), 404

    @app.get("/")
    def index() -> str:
        return render_template("dashboard/index.html")

    @app.get("/sessions")
    def sessions_view() -> str:
        return render_template("dashboard/sessions.html")

    @app.get("/session/<session_id>")
    def session_detail_view(session_id: str) -> str:
        return render_template("dashboard/session_detail.html", session_id=session_id)

    @app.get("/alerts")
    def alerts_view() -> str:
        return render_template("dashboard/alerts.html")

    @app.get("/analytics")
    def analytics_view() -> str:
        return render_template("dashboard/analytics.html")

    @app.get("/credentials")
    def credentials_view() -> str:
        return render_template("dashboard/credentials.html")

    @app.get("/commands")
    def commands_view() -> str:
        return render_template("dashboard/commands.html")

    @app.get("/http")
    def http_view() -> str:
        return render_template("dashboard/http.html")

    @app.get("/search")
    def search_view() -> str:
        return render_template("dashboard/search.html")

    @app.get("/services")
    def services_view() -> str:
        return render_template("dashboard/services.html")

    @app.get("/api/live")
    def api_live() -> Any:
        services = _with_active_counts(database.list_services(), listeners)
        return jsonify(
            {
                "summary": analytics.summary(),
                "services": services,
                "recent_sessions": database.list_sessions(limit=25),
                "active_sessions": [_session_to_dict(s) for s in session_manager.list_active_sessions()],
            }
        )

    @app.get("/api/analytics")
    def api_analytics() -> Any:
        return jsonify(
            {
                "summary": analytics.summary(),
                "services": _with_active_counts(analytics.services(), listeners),
                "top_attackers": analytics.top_attackers(),
                "protocol_distribution": analytics.protocol_distribution(),
                "severity_distribution": analytics.severity_distribution(),
                "top_usernames": analytics.top_usernames(),
                "top_passwords": analytics.top_passwords(),
                "top_threats": analytics.top_threats(),
                "top_urls": analytics.top_urls(),
                "top_commands": analytics.top_commands(),
                "top_ftp_commands": analytics.top_ftp_commands(),
                "most_targeted_services": analytics.most_targeted_services(),
                "attack_timeline": analytics.attack_timeline(),
                "session_timeline": analytics.session_timeline(),
                "geographic_distribution": analytics.geographic_distribution(),
            }
        )

    @app.get("/api/services")
    def api_services() -> Any:
        return jsonify(_with_active_counts(database.list_services(), listeners))

    @app.get("/api/sessions")
    def api_sessions() -> Any:
        return jsonify(
            analytics.search_sessions(
                ip=_arg("ip"),
                protocol=_arg("protocol"),
                severity=_arg("severity"),
                limit=_limit(),
            )
        )

    @app.get("/api/session/<session_id>")
    def api_session(session_id: str) -> Any:
        details = analytics.session_details(session_id)
        if not details:
            return jsonify({"error": "Session not found"}), 404
        return jsonify(details)

    @app.get("/api/alerts")
    def api_alerts() -> Any:
        return jsonify(
            analytics.search_alerts(
                ip=_arg("ip"),
                threat_type=_arg("threat_type"),
                severity=_arg("severity"),
                limit=_limit(),
            )
        )

    @app.post("/api/alerts/<int:alert_id>/ack")
    def api_ack_alert(alert_id: int) -> Any:
        database.acknowledge_alert(alert_id)
        return jsonify({"ok": True})

    @app.get("/api/credentials")
    def api_credentials() -> Any:
        rows = analytics.search_credentials(
            username=_arg("username"),
            password=_arg("password"),
            ip=_arg("ip"),
            limit=_limit(),
        )
        return jsonify([_with_analysis(row, analyze_credential(row)) for row in rows])

    @app.get("/api/commands")
    def api_commands() -> Any:
        rows = analytics.search_commands(
            command=_arg("command"),
            protocol=_arg("protocol"),
            ip=_arg("ip"),
            limit=_limit(),
        )
        return jsonify([_with_analysis(row, analyze_command(row)) for row in rows])

    @app.get("/api/http")
    def api_http() -> Any:
        return jsonify(
            analytics.search_http(
                method=_arg("method"),
                path=_arg("path"),
                ip=_arg("ip"),
                limit=_limit(),
            )
        )

    @app.post("/api/admin/clear")
    def api_admin_clear() -> Any:
        deleted = database.clear_captured_data()
        log_result = _clear_log_files(config.logging.directory)
        return jsonify(
            {
                "ok": True,
                "deleted": deleted,
                "logs": log_result,
            }
        )

    # ------------------------------------------------------------------ #
    # Data export (CSV / JSON)
    # ------------------------------------------------------------------ #
    def _export_datasets() -> dict[str, Callable[[], list[dict[str, Any]]]]:
        """Map an export dataset name to a filtered row producer.

        Each producer honours the same query-string filters as the matching
        list endpoint so exports reflect the analyst's current view.
        """
        return {
            "sessions": lambda: analytics.search_sessions(
                ip=_arg("ip"), protocol=_arg("protocol"),
                severity=_arg("severity"), limit=_limit(default=2000),
            ),
            "credentials": lambda: analytics.search_credentials(
                username=_arg("username"), password=_arg("password"),
                ip=_arg("ip"), limit=_limit(default=2000),
            ),
            "commands": lambda: analytics.search_commands(
                command=_arg("command"), protocol=_arg("protocol"),
                ip=_arg("ip"), limit=_limit(default=2000),
            ),
            "http": lambda: analytics.search_http(
                method=_arg("method"), path=_arg("path"),
                ip=_arg("ip"), limit=_limit(default=2000),
            ),
            "alerts": lambda: analytics.search_alerts(
                ip=_arg("ip"), threat_type=_arg("threat_type"),
                severity=_arg("severity"), limit=_limit(default=2000),
            ),
        }

    @app.get("/api/export/<dataset>")
    def api_export(dataset: str) -> Any:
        datasets = _export_datasets()
        producer = datasets.get(dataset)
        if producer is None:
            return jsonify({"error": f"Unknown dataset '{dataset}'"}), 404
        rows = producer() or []
        fmt = (request.args.get("format", "csv") or "csv").lower()
        filename = f"aegistrap_{dataset}.{ 'json' if fmt == 'json' else 'csv' }"
        if fmt == "json":
            payload = jsonify(rows)
            payload.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
            return payload
        body = _rows_to_csv(rows)
        return Response(
            body,
            mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/health")
    def health() -> Any:
        return jsonify({"ok": True, "version": __version__})

    def _arg(name: str) -> str | None:
        value = request.args.get(name, "").strip()
        return value or None

    def _limit(default: int = 100, maximum: int = 2000) -> int:
        try:
            value = int(request.args.get("limit", default))
        except (TypeError, ValueError):
            value = default
        return max(1, min(maximum, value))

    return app


def _rows_to_csv(rows: list[dict[str, Any]]) -> str:
    """Serialise a list of row dicts to CSV text.

    The column set is the union of keys across all rows (stable order:
    first-seen). Nested/JSON values are stringified so the file stays flat.
    """
    if not rows:
        return ""
    columns: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row.keys():
            if key not in seen and key != "analysis":
                seen.add(key)
                columns.append(key)
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        flat = {}
        for key in columns:
            value = row.get(key, "")
            if isinstance(value, (dict, list)):
                flat[key] = _json_compact(value)
            else:
                flat[key] = value
        writer.writerow(flat)
    return buffer.getvalue()


def _json_compact(value: Any) -> str:
    import json

    try:
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


def _session_to_dict(session: Any) -> dict[str, Any]:
    if hasattr(session, "to_db_row"):
        return session.to_db_row()
    return dict(session)


def _with_analysis(row: dict[str, Any], analysis: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(row)
    enriched["analysis"] = analysis
    return enriched


def _clear_log_files(log_dir: str) -> dict[str, Any]:
    target = Path(log_dir)
    removed: list[str] = []
    failed: list[dict[str, str]] = []
    if not target.exists():
        return {"removed": removed, "failed": failed}
    for path in target.glob("*.log*"):
        if not path.is_file():
            continue
        try:
            path.write_text("", encoding="utf-8")
            removed.append(str(path))
        except OSError as exc:
            failed.append({"path": str(path), "error": str(exc)})
    return {"removed": removed, "failed": failed}


def _with_active_counts(
    services: list[dict[str, Any]], listeners: dict[str, Any]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for service in services:
        row = dict(service)
        listener = listeners.get(str(row.get("name", "")))
        active = getattr(listener, "active_connections", None)
        if callable(active):
            active = active()
        if active is None:
            active = getattr(listener, "active_count", 0) if listener is not None else 0
        row["active_connections"] = int(active or 0)
        rows.append(row)
    return rows
