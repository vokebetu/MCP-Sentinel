import os
from pathlib import Path

import pytest
import requests

FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:8501").rstrip("/")
SCREENSHOTS = os.environ.get("SCREENSHOT_DIR")


def frontend_up():
    try:
        return requests.get(f"{FRONTEND_URL}/_stcore/health", timeout=3).ok
    except requests.RequestException:
        return False


pytestmark = pytest.mark.skipif(not frontend_up(), reason="frontend is not running")


@pytest.fixture(scope="module")
def page():
    playwright = pytest.importorskip("playwright.sync_api")
    with playwright.sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(viewport={"width": 1500, "height": 1000})
        yield context.new_page()
        browser.close()


def shot(page, name):
    if SCREENSHOTS:
        Path(SCREENSHOTS).mkdir(parents=True, exist_ok=True)
        page.wait_for_timeout(1500)
        page.screenshot(path=str(Path(SCREENSHOTS) / f"{name}.png"), full_page=True)


def wait_text(page, text, timeout=60000):
    page.get_by_text(text, exact=False).first.wait_for(timeout=timeout)


def choose_server(page, label, query):
    box = page.get_by_label(label)
    box.fill(query)
    box.press("Enter")
    wait_text(page, "Matching servers")


def test_dashboard_shows_database_statistics(page):
    page.goto(FRONTEND_URL)
    wait_text(page, "Registry records")
    wait_text(page, "Enrichment is partial")
    wait_text(page, "Non-deleted servers")
    wait_text(page, "Vulnerability assessment state")
    wait_text(page, "Known limitations")
    shot(page, "01_dashboard")


def test_search_finds_a_server(page):
    page.goto(f"{FRONTEND_URL}/search")
    wait_text(page, "Server search")
    page.get_by_label("Keyword").fill("praisonai")
    page.get_by_test_id("stBaseButton-primaryFormSubmit").click()
    wait_text(page, "1 matching servers")


def test_profile_shows_findings_and_coverage(page):
    page.goto(f"{FRONTEND_URL}/profile")
    choose_server(page, "Find a server", "praisonai")
    wait_text(page, "io.github.MervinPraison/praisonai")
    page.get_by_role("tab", name="Observed concerns").click()
    wait_text(page, "Indicator A")
    wait_text(page, "Known vulnerabilities in declared package versions")
    wait_text(page, "Modeled dependency exposures")
    shot(page, "04_profile_praisonai_concerns")
    page.get_by_role("tab", name="Assessment coverage").click()
    wait_text(page, "Indicator B")
    shot(page, "05_profile_praisonai_coverage")


def test_unassessed_server_is_not_shown_as_safe(page):
    page.goto(f"{FRONTEND_URL}/profile")
    choose_server(page, "Find a server", "ac.inference.sh/mcp")
    wait_text(page, "No vulnerability lookup has been recorded")
    page.get_by_role("tab", name="Observed concerns").click()
    wait_text(page, "unknown, not zero")


def test_compare_two_servers(page):
    page.goto(f"{FRONTEND_URL}/compare")
    choose_server(page, "First server", "praisonai")
    choose_server(page, "Second server", "ac.inference.sh/mcp")
    wait_text(page, "different assessment coverage")
    wait_text(page, "unknown rather than zero")
    shot(page, "07_compare")
