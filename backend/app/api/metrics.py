"""Prometheus `/metrics` endpoint (M14.a)."""

from __future__ import annotations

from fastapi import APIRouter, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

router = APIRouter(prefix="/metrics", tags=["meta"])


@router.get("", include_in_schema=False)
def metrics() -> Response:
    """Returns the prometheus-format scrape body. Unauthenticated;
    rely on the manager LB / ingress to keep this off the public
    network."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
