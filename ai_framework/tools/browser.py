"""browser_render — render a page in a headless browser so JS-heavy bugs are testable.

The urllib tools can't run JavaScript, so DOM XSS, SPA routes, and client-side rendered content
are invisible to them. This tool drives a headless Chromium (via the optional ``playwright``
extra) to fetch the *rendered* DOM. It is:

* **scope-gated** like every network tool (localhost or an authorized target);
* **optional** — Playwright is an extra (`pip install -e ".[browser]"` + `playwright install
  chromium`); if it isn't present the tool returns a clear message instead of crashing;
* **injectable** — ``ctx.renderer`` overrides the real browser, so tests exercise the logic
  (scope gate, truncation, missing-engine) without launching anything.

Read-only: it navigates and returns the DOM/console; it does not submit forms on its own.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from ai_framework.tools.base import ToolContext, require_authorized

_MAX_HTML = 12000
_DEFAULT_WAIT_MS = 1500


def _playwright_render(
    url: str, wait_ms: int, scope_validator: Callable[[str], None]
) -> str:
    """Render with headless Chromium. Raises ImportError if Playwright isn't installed."""
    from playwright.sync_api import sync_playwright  # lazy: only needed when actually rendering

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            context = browser.new_context()
            blocked: list[str] = []

            def gate(route: Any) -> None:
                try:
                    scope_validator(route.request.url)
                except PermissionError:
                    blocked.append(route.request.url)
                    route.abort("blockedbyclient")
                    return
                route.continue_()

            context.route("**/*", gate)
            page = context.new_page()
            page.goto(url, wait_until="networkidle", timeout=30000)
            if wait_ms:
                page.wait_for_timeout(wait_ms)
            title = page.title()
            html = page.content()
        finally:
            browser.close()
    notice = f"<!-- blocked off-scope requests: {len(blocked)} -->\n" if blocked else ""
    return f"{notice}<!-- title: {title} -->\n{html}"


class BrowserRenderTool:
    name = "browser_render"
    description = (
        "Render a page in a headless browser and return the JS-executed DOM — use for DOM XSS, "
        "SPA routes, and client-rendered content the HTTP tools can't see. Read-only, scope-gated. "
        "Requires the optional 'browser' extra; says so if it's not installed."
    )
    touches_network = True
    mutating = False

    @property
    def json_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Absolute http(s) URL (scope-gated)"},
                "wait_ms": {"type": "integer", "description": "Extra settle time after load (ms)"},
            },
            "required": ["url"],
        }

    def run(self, args: dict[str, Any], ctx: ToolContext) -> str:
        url = args["url"]
        require_authorized(url, ctx)
        wait_ms = int(args.get("wait_ms", _DEFAULT_WAIT_MS))
        try:
            if ctx.renderer is not None:
                html = ctx.renderer(url, wait_ms)
            else:
                if os.getenv("SECFORGE_ALLOW_HOST_BROWSER", "") != "1":
                    return (
                        "[browser_render] blocked: no isolated browser renderer is configured. "
                        "Set ToolContext.renderer to a sandboxed renderer; host browser execution "
                        "is disabled."
                    )

                def validate(candidate: str) -> None:
                    require_authorized(candidate, ctx)

                html = _playwright_render(url, wait_ms, validate)
        except ImportError:
            return (
                "[browser_render] Playwright not installed — run `pip install -e \".[browser]\"` "
                "then `playwright install chromium`, or use the HTTP tools for non-JS content."
            )
        except Exception as exc:  # noqa: BLE001 - a render failure degrades, doesn't crash the loop
            return f"[browser_render] render failed for {url}: {type(exc).__name__}: {exc}"
        html = str(html)
        if len(html) > _MAX_HTML:
            html = html[:_MAX_HTML] + "\n… [truncated]"
        return f"rendered {url}\n{html}"
