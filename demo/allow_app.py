"""Demo Allow-page app: the reference router plus a small home page.

In real use this router lives inside an app that is already behind your SSO (an internal
portal, an admin site). Here it runs on its own, with the demo-only fake login.

    PYTHONPATH=reference uvicorn allow_app:app --app-dir demo --port 8001
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from allow_page import APP_NAME, router

app = FastAPI(title=f"{APP_NAME} · Allow page", docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(router)


@app.get("/", response_class=HTMLResponse)
async def home() -> str:
    return (f"<!doctype html><meta charset=utf-8><title>{APP_NAME}</title>"
            "<body style='font:15px system-ui;max-width:560px;margin:10vh auto;padding:0 16px'>"
            f"<h1>{APP_NAME}: Allow page</h1><p>This host only shows the page where people approve an "
            "AI agent. Your agent opens it for you when you connect to the MCP server.</p></body>")
