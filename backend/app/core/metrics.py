"""Prometheus metrics for the manager (M14.a).

Exposes Counter / Histogram / Gauge singletons that the request
middleware + the gRPC service + the Kafka producer wrapper update.
The `/metrics` route in `app.api.metrics` serves the registry in
prometheus text format.

We use the global `prometheus_client.REGISTRY` so any metric
registered anywhere in the app appears at `/metrics` automatically.
That means a contributor adding a new counter doesn't need to touch
this file beyond importing.
"""
from __future__ import annotations

from typing import Final

from prometheus_client import Counter, Gauge, Histogram

# HTTP request metrics, populated by RequestMetricsMiddleware.
requests_total: Final[Counter] = Counter(
    "edr_manager_requests_total",
    "Total HTTP requests handled by the manager.",
    labelnames=("method", "route", "status"),
)
request_latency_seconds: Final[Histogram] = Histogram(
    "edr_manager_request_latency_seconds",
    "Latency of HTTP requests handled by the manager (seconds).",
    labelnames=("method", "route"),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

# gRPC stream metrics, populated by AgentService.HostStream.
grpc_active_streams: Final[Gauge] = Gauge(
    "edr_manager_grpc_active_streams",
    "Number of currently-open agent HostStream sessions.",
)

# Pipeline counters.
kafka_produce_total: Final[Counter] = Counter(
    "edr_manager_kafka_produce_total",
    "Kafka records produced by the manager (telemetry.raw + alerts.raw).",
    labelnames=("topic",),
)
opensearch_index_total: Final[Counter] = Counter(
    "edr_manager_opensearch_index_total",
    "Documents indexed into OpenSearch by the indexer worker.",
    labelnames=("index_pattern",),
)

# Alert + command lifecycle.
alerts_opened_total: Final[Counter] = Counter(
    "edr_manager_alerts_opened_total",
    "Alerts opened by the detector + sigma_realtime workers.",
    labelnames=("severity", "rule_kind"),
)
commands_queued_total: Final[Counter] = Counter(
    "edr_manager_commands_queued_total",
    "Commands queued via /api/hosts/{id}/commands or auto-action.",
    labelnames=("kind",),
)
