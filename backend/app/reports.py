"""Compatibility shim for the legacy ``app.reports`` module.

The report engine now lives in :mod:`app.reporting`, split into a normalised
model and format-specific renderers. This module keeps existing imports
working without duplicating rendering logic.
"""
from .reporting import (  # noqa: F401
    COMPANY,
    METHOD_VERSION,
    PRODUCT,
    RENDER,
    REPORT_SCHEMA,
    TAGLINE,
    build,
    render_csv,
    render_html,
    render_json,
    render_pdf,
)

__all__ = [
    "build", "render_html", "render_pdf", "render_json", "render_csv", "RENDER",
    "PRODUCT", "COMPANY", "TAGLINE", "REPORT_SCHEMA", "METHOD_VERSION",
]
