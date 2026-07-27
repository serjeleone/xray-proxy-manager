from __future__ import annotations

import contextlib
import os
import re
import shutil
from pathlib import Path

import pytest
from playwright.sync_api import Browser, Page, sync_playwright

ROOT = Path(__file__).parents[2]
WEB_ROOT = ROOT / "xray-proxy-manager" / "web"


@pytest.fixture(scope="session")
def web_app_html() -> str:
    index = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
    style = (WEB_ROOT / "style.css").read_text(encoding="utf-8")
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    script = script.replace(
        "const api = (path) => new URL(path.replace(/^\\//, ''), window.location.href.endsWith('/') ? window.location.href : `${window.location.href}/`).toString();",
        "const api = (path) => new URL(path.replace(/^\\//, ''), 'https://app.test/').toString();",
    )
    index = re.sub(r'<link rel="stylesheet" href="style\.css\?ui=\d+">', lambda _match: f"<style>{style}</style>", index)
    index = re.sub(r'<script src="app\.js\?ui=\d+"></script>', lambda _match: f"<script>{script}</script>", index)
    return index


@pytest.fixture(scope="session")
def browser() -> Browser:
    with sync_playwright() as playwright:
        executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE") or shutil.which("chromium")
        launch_options: dict[str, object] = {"headless": True, "args": ["--no-sandbox"]}
        if executable:
            launch_options["executable_path"] = executable
        browser = playwright.chromium.launch(**launch_options)
        try:
            yield browser
        finally:
            browser.close()


@pytest.fixture
def page(browser: Browser) -> Page:
    context = browser.new_context(locale="ru-RU", viewport={"width": 1440, "height": 1000})
    page = context.new_page()
    page_errors: list[str] = []
    page.on("pageerror", lambda error: page_errors.append(str(error)))
    try:
        yield page
        assert not page_errors, f"JavaScript errors in UI: {page_errors}"
    finally:
        with contextlib.suppress(Exception):
            context.close()
