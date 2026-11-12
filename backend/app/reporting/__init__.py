"""ZeroDay's LLM Rakshak evidence-aware reporting package."""
from .exports import render_csv, render_json
from .html import render_html
from .model import COMPANY, METHOD_VERSION, PRODUCT, REPORT_SCHEMA, TAGLINE, build
from .pdf import render_pdf

RENDER = {
    "html": (render_html, "text/html; charset=utf-8"),
    "json": (render_json, "application/json"),
    "csv": (render_csv, "text/csv"),
    "pdf": (render_pdf, "application/pdf"),
}

__all__ = [
    "build", "render_html", "render_pdf", "render_json", "render_csv", "RENDER",
    "PRODUCT", "COMPANY", "TAGLINE", "REPORT_SCHEMA", "METHOD_VERSION",
]
