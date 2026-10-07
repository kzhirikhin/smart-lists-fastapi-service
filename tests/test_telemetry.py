"""Нативная телеметрия не получает запросы даже при настроенном окружении."""

from contextlib import ExitStack
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app


def test_native_telemetry_stays_disabled_with_global_providers(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:9")
    monkeypatch.setenv("OTEL_SDK_DISABLED", "false")

    async def fail():
        raise RuntimeError("private exception sentinel")

    original_routes = list(app.router.routes)
    app.add_api_route("/telemetry-test-error", fail)
    try:
        with ExitStack() as stack:
            # Настроенные глобальные провайдеры тоже не должны получать данные.
            spies = [
                stack.enter_context(patch(target))
                for target in (
                    "opentelemetry.trace.get_tracer_provider",
                    "opentelemetry.metrics.get_meter_provider",
                    "opentelemetry._logs.get_logger_provider",
                    "fastapi.telemetry._runtime._export_endpoint",
                )
            ]
            with TestClient(app, raise_server_exceptions=False) as client:
                assert client.get("/health").status_code == 200
                assert client.post("/insights", content="private body").status_code == 403
                assert client.post(
                    "/insights", json={}, headers={"Authorization": "Bearer test"}
                ).status_code == 422
                assert client.get("/telemetry-test-error").status_code == 500
            for spy in spies:
                spy.assert_not_called()
    finally:
        app.router.routes[:] = original_routes
