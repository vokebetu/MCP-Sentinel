import csv
import io
import os
import re
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
    wait_text(page, "Package vulnerability lookups cover")
    wait_text(page, "Non-deleted servers")
    wait_text(page, "Vulnerability assessment state")
    wait_text(page, "Known limitations")
    shot(page, "01_dashboard")


SEARCH_BOX = "Search by server name, title or description"


def search_for(page, text, expect=None):
    box = page.get_by_placeholder(SEARCH_BOX)
    box.fill(text)
    box.press("Enter")
    if expect:
        for _ in range(100):
            rows = grid_rows(page)
            if rows and rows[0][1].endswith("#" + expect):
                page.wait_for_timeout(500)
                return
            page.wait_for_timeout(300)
        raise AssertionError(f"{expect} did not appear as the first result")


def grid_rows(page):
    cells = page.locator('[data-testid="stDataFrame"] [role="gridcell"]').all_inner_texts()
    width = len(page.locator('[data-testid="stDataFrame"] [role="columnheader"]').all_inner_texts())
    return [cells[i:i + width] for i in range(0, len(cells), width)] if width else []


def tick(page, row):
    before = selected_count(page)
    box = page.locator('[data-testid="stDataFrame"]').first.bounding_box()
    page.mouse.click(box["x"] + 38, box["y"] + 36 + 35 * row + 17)
    for _ in range(40):
        page.wait_for_timeout(250)
        if selected_count(page) != before:
            break
    page.wait_for_timeout(600)


def selected_count(page):
    bar = page.locator(".st-key-selection_bar")
    if not bar.count():
        return 0
    return int(re.search(r"(\d+) selected", bar.inner_text()).group(1))


def open_search(page):
    page.goto(f"{FRONTEND_URL}/search")
    wait_text(page, "showing 1–25")
    page.wait_for_timeout(1200)


def test_search_finds_a_server(page):
    open_search(page)
    search_for(page, "praisonai", expect="io.github.MervinPraison/praisonai")
    wait_text(page, "1 server ·")


def page_label(page):
    text = page.get_by_text(re.compile(r"Showing [\d,]+–[\d,]+ of")).first.inner_text()
    first, last, page_no = re.search(r"Showing ([\d,]+)–([\d,]+) of [\d,]+ · page ([\d,]+)", text).groups()
    return int(first.replace(",", "")), int(last.replace(",", "")), int(page_no.replace(",", ""))


def no_api_errors(page):
    alerts = " ".join(page.locator('[data-testid="stAlert"]').all_inner_texts())
    return "HTTP 503" not in alerts and "not reachable" not in alerts and "took too long" not in alerts


def test_pagination_sequence_is_exact(page):
    open_search(page)
    for number in (2, 3, 4, 5):
        page.get_by_role("button", name="Next ▶").click()
        wait_text(page, f"showing {(number - 1) * 25 + 1}–{number * 25}")
    for number in (4, 3, 2, 1):
        page.get_by_role("button", name="◀ Previous").click()
        wait_text(page, f"showing {(number - 1) * 25 + 1}–{number * 25}")
    assert no_api_errors(page)


def test_rapid_pagination_has_no_errors(page):
    open_search(page)
    for _ in range(6):
        page.get_by_role("button", name="Next ▶").click()
        page.wait_for_timeout(200)
    for _ in range(5):
        page.get_by_role("button", name="◀ Previous").click()
        page.wait_for_timeout(200)
    page.wait_for_timeout(4000)
    first, last, number = page_label(page)
    assert (first, last) == ((number - 1) * 25 + 1, number * 25)
    assert no_api_errors(page)


def test_filters_page_and_selection_survive_navigation(page):
    open_search(page)
    page.get_by_role("button", name="Has vulnerabilities").click()
    wait_text(page, "Vulnerability evidence: Findings recorded")
    page.get_by_role("button", name="Next ▶").click()
    wait_text(page, "showing 26–50")
    page.wait_for_timeout(1200)
    tick(page, 0)
    tick(page, 1)
    assert selected_count(page) == 2
    for name in ("Server profile", "Compare", "AI assistant", "Server search"):
        page.get_by_role("link", name=name).click()
        page.wait_for_timeout(1500)
    wait_text(page, "showing 26–50")
    wait_text(page, "Vulnerability evidence: Findings recorded")
    assert selected_count(page) == 2
    rows = grid_rows(page)
    assert rows[0][0] == "true" and rows[1][0] == "true"
    page.get_by_role("button", name="Clear", exact=True).click()
    page.get_by_role("button", name="Clear all").click()
    wait_text(page, "48,")


def test_selection_spans_pages_and_select_all_is_page_only(page):
    open_search(page)
    tick(page, 0)
    tick(page, 1)
    page.get_by_role("button", name="Next ▶").click()
    wait_text(page, "showing 26–50")
    page.wait_for_timeout(1200)
    tick(page, 2)
    assert selected_count(page) == 3
    page.get_by_role("button", name="◀ Previous").click()
    wait_text(page, "showing 1–25")
    page.wait_for_timeout(1500)
    rows = grid_rows(page)
    assert rows[0][0] == "true" and rows[1][0] == "true" and rows[2][0] == "false"
    page.get_by_text("Select all on this page").click()
    page.wait_for_timeout(1500)
    assert selected_count(page) == 26
    page.get_by_text("Select all on this page").click()
    page.wait_for_timeout(1500)
    assert selected_count(page) == 1
    page.get_by_role("button", name="Clear", exact=True).click()


def test_visible_page_export_matches_screen(page):
    open_search(page)
    search_for(page, "postgres")
    page.wait_for_timeout(2500)
    with page.expect_download() as download:
        page.get_by_role("button", name="Export visible page (CSV)").click()
    rows = list(csv.DictReader(io.StringIO(Path(download.value.path()).read_text(encoding="utf-8"))))
    shown = grid_rows(page)
    assert rows and len(rows) <= 25 and shown
    for screen, exported in zip(shown, rows):
        server_id, name = re.match(r"profile\?server_id=(\d+)#(.+)$", screen[1]).groups()
        assert exported["Server ID"] == server_id and exported["Server"] == name
        assert exported["Vulnerability evidence ⓘ"] == screen[5] and exported["Tools ⓘ"] == screen[6]
        assert exported["Repo"] == (screen[7] or "Not declared")


def test_profile_shows_repository_tools_and_ask_ai(page):
    page.goto(f"{FRONTEND_URL}/profile")
    choose_server(page, "Find a server", "praisonai")
    wait_text(page, "io.github.MervinPraison/praisonai")
    assert page.get_by_role("link", name="View repository").get_attribute("href").startswith("https://github.com/")
    page.get_by_role("tab", name="Tools").click()
    wait_text(page, "Tool metadata:")
    ask = page.get_by_role("button", name="Ask AI about this server")
    if ask.is_disabled():
        return
    ask.click()
    wait_text(page, "Server: io.github.MervinPraison/praisonai")


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


def test_profile_review_checklist(page):
    page.goto(f"{FRONTEND_URL}/profile")
    choose_server(page, "Find a server", "praisonai")
    wait_text(page, "io.github.MervinPraison/praisonai")
    page.get_by_role("tab", name="Review checklist").click()
    wait_text(page, "items need attention")
    wait_text(page, "Software bill of materials (SBOM)")
    wait_text(page, "Download SBOM (CycloneDX JSON)")
    shot(page, "09_review_checklist")


def test_unassessed_server_is_not_shown_as_safe(page):
    page.goto(f"{FRONTEND_URL}/profile")
    choose_server(page, "Find a server", "ai.agentplaybooks/agentplaybooks")
    wait_text(page, "No installable package is declared")
    page.get_by_role("tab", name="Observed concerns").click()
    wait_text(page, "unknown, not zero")


def test_compare_two_servers(page):
    open_search(page)
    for query, name in (("praisonai", "io.github.MervinPraison/praisonai"), ("ai.agentplaybooks/agentplaybooks", "ai.agentplaybooks/agentplaybooks")):
        search_for(page, query, expect=name)
        tick(page, 0)
    assert selected_count(page) == 2
    page.get_by_role("button", name="Compare selected").click()
    wait_text(page, "Show differences only")
    wait_text(page, "different assessment coverage")
    wait_text(page, "package checks not applicable")
    assert page.get_by_text("unknown rather than zero").count() == 0
    table = page.locator("table.cmp").first
    assert table.locator("thead a").count() == 2 and "Registry name" not in table.inner_text()
    assert table.locator("td.diff").count() > 0
    shot(page, "07_compare")
    before = table.locator("tbody tr").count()
    page.get_by_text("Show differences only").click()
    page.wait_for_timeout(2000)
    assert page.locator("table.cmp").first.locator("tbody tr").count() < before
    page.get_by_text("How we got this data").click()
    wait_text(page, "Advisories for declared packages")
    page.get_by_role("button", name="Remove").first.click()
    wait_text(page, "Choose at least two servers")


@pytest.mark.skipif(os.environ.get("RUN_LIVE_AI_TESTS") != "1", reason="set RUN_LIVE_AI_TESTS=1 to allow live model requests")
def test_ai_assistant_answers_with_sources_and_clears_history(page):
    page.goto(f"{FRONTEND_URL}/ai")
    wait_text(page, "evidence chunks")
    wait_text(page, "What do you want to know?")
    if page.get_by_role("button", name="New chat").count():
        page.get_by_role("button", name="New chat").click()
        wait_text(page, "What do you want to know?")
    question = page.get_by_placeholder("Ask about a server, vulnerability, or missing assessment")
    question.fill("How many direct advisories are recorded for praisonai?")
    question.press("Enter")
    wait_text(page, "Sources (", timeout=110000)
    answer = page.get_by_test_id("stChatMessage").last.inner_text()
    assert "81" in answer and re.search(r"\[\d+\]", answer)
    if SCREENSHOTS:
        page.screenshot(path=str(Path(SCREENSHOTS) / "08_ai_answer.png"), full_page=False)
    page.get_by_text("Sources (", exact=False).last.click()
    wait_text(page, "[1]")
    shot(page, "08_ai_answer_sources")
    page.get_by_role("link", name="Server search").click()
    page.wait_for_timeout(1500)
    page.get_by_role("link", name="AI assistant").click()
    wait_text(page, "How many direct advisories are recorded for praisonai?")
    question = page.get_by_placeholder("Ask about a server, vulnerability, or missing assessment")
    question.fill("Do those findings prove which dependencies are installed?")
    question.press("Enter")
    page.get_by_test_id("stChatMessage").nth(3).wait_for(timeout=110000)
    wait_text(page, "input /", timeout=110000)
    shot(page, "09_ai_followup")
    page.get_by_role("button", name="New chat").click()
    wait_text(page, "What do you want to know?")
    assert page.get_by_test_id("stChatMessage").count() == 0


@pytest.mark.skipif(os.environ.get("RUN_LIVE_AI_TESTS") != "1", reason="set RUN_LIVE_AI_TESTS=1 to allow live model requests")
def test_ai_example_card_submits_and_is_hidden_after(page):
    page.goto(f"{FRONTEND_URL}/ai")
    wait_text(page, "What do you want to know?")
    page.locator(".st-key-ai_cards button").first.click()
    wait_text(page, "Sources (", timeout=110000)
    assert page.locator(".st-key-ai_cards").count() == 0
    assert re.search(r"\[\d+\]", page.get_by_test_id("stChatMessage").last.inner_text())
    page.get_by_role("button", name="New chat").click()
    wait_text(page, "What do you want to know?")


def pick_page_size(page, size):
    combo, option = page.get_by_role("combobox", name="Rows per page"), page.get_by_role("option", name=f"{size} per page")
    for _ in range(3):
        combo.scroll_into_view_if_needed()
        page.wait_for_timeout(500)
        combo.click()
        page.wait_for_timeout(800)
        if option.count():
            option.click()
            return
    raise AssertionError("the rows-per-page menu did not open")


def test_page_size_changes_rows_paging_export_and_keeps_selection(page):
    open_search(page)
    tick(page, 0)
    assert selected_count(page) == 1
    pick_page_size(page, 10)
    wait_text(page, "showing 1–10")
    page.wait_for_timeout(1200)
    assert len(grid_rows(page)) == 10 and page_label(page) == (1, 10, 1)
    page.get_by_role("button", name="Next ▶").click()
    wait_text(page, "showing 11–20")
    assert page_label(page) == (11, 20, 2)
    pick_page_size(page, 50)
    wait_text(page, "showing 1–50")
    page.wait_for_timeout(1500)
    assert page_label(page) == (1, 50, 1) and selected_count(page) == 1
    page.get_by_role("button", name="Next ▶").click()
    wait_text(page, "showing 51–100")
    for name in ("Compare", "Server search"):
        page.get_by_role("link", name=name).click()
        page.wait_for_timeout(1500)
    wait_text(page, "showing 51–100")
    with page.expect_download() as download:
        page.get_by_role("button", name="Export visible page (CSV)").click()
    rows = list(csv.DictReader(io.StringIO(Path(download.value.path()).read_text(encoding="utf-8"))))
    assert len(rows) == 50 and selected_count(page) == 1 and no_api_errors(page)
    pick_page_size(page, 100)
    wait_text(page, "showing 1–100")
    pick_page_size(page, 25)
    wait_text(page, "showing 1–25")
    page.get_by_role("button", name="Clear", exact=True).click()


def styles(page, selector):
    return page.locator(selector).first.evaluate("e => { const c = getComputedStyle(e); return [c.backgroundColor, c.borderTopColor, "
                                                 "c.borderTopWidth, c.boxShadow]; }")


def test_text_inputs_are_white_bordered_and_show_focus(page):
    open_search(page)
    root = '.st-key-search_box [data-testid="stTextInputRootElement"]'
    background, border, width, _ = styles(page, root)
    assert background == "rgb(255, 255, 255)" and border == "rgb(140, 147, 160)" and width == "1px"
    placeholder = page.locator(f"{root} input").evaluate("e => getComputedStyle(e, '::placeholder').color")
    assert placeholder == "rgb(107, 114, 128)"
    page.get_by_placeholder(SEARCH_BOX).focus()
    page.wait_for_timeout(300)
    assert "rgba(31, 79, 196" in styles(page, root)[3] and styles(page, root)[1] == "rgb(31, 79, 196)"
    assert styles(page, '.st-key-f_page_size [role="group"]')[0] == "rgb(255, 255, 255)"
    search_for(page, "ac.snag/snag", expect="ac.snag/snag")
    row = grid_rows(page)[0]
    assert row[3] == "1.0.0" and row[4] == "Remote only" and row[5] == "— Not applicable" and row[6] == "Not observed"
    shot(page, "02_search_snag")
    page.goto(f"{FRONTEND_URL}/ai")
    wait_text(page, "AI assistant")
    page.wait_for_timeout(2500)
    if page.locator('[data-testid="stChatInput"]').count():
        background, border, width, _ = styles(page, '[data-testid="stChatInput"] > div')
        assert background == "rgb(255, 255, 255)" and border == "rgb(140, 147, 160)" and width == "1px"
    shot(page, "11_ai_input")


@pytest.mark.skipif(os.environ.get("RUN_LIVE_AI_TESTS") != "1", reason="set RUN_LIVE_AI_TESTS=1 to allow live model requests")
def test_ai_named_server_overrides_stale_scope_and_follow_up_keeps_it(page):
    open_search(page)
    for name in ("ai.azquo/azquo", "ai.leadmcp/leadmcp"):
        search_for(page, name, expect=name)
        tick(page, 0)
    assert selected_count(page) == 2
    page.get_by_role("button", name="Ask AI").click()
    wait_text(page, "Server: 2 servers")
    question = page.get_by_placeholder("Ask about a server, vulnerability, or missing assessment")
    question.fill("What version is ac.snag/snag?")
    question.press("Enter")
    wait_text(page, "Sources (", timeout=110000)
    answer = page.get_by_test_id("stChatMessage").last.inner_text()
    assert "1.0.0" in answer and re.search(r"\[\d+\]", answer) and "azquo" not in answer.split("Scope used")[0]
    wait_text(page, "Scope used: ac.snag/snag (named in the question)")
    wait_text(page, "Selected but not used for this answer: ai.azquo/azquo, ai.leadmcp/leadmcp")
    page.get_by_text("Sources (", exact=False).last.click()
    wait_text(page, "ac.snag/snag: registry record")
    shot(page, "10_ai_stale_scope_fixed")
    question = page.get_by_placeholder("Ask about a server, vulnerability, or missing assessment")
    question.fill("Does it declare a package?")
    question.press("Enter")
    page.get_by_test_id("stChatMessage").nth(3).wait_for(timeout=110000)
    wait_text(page, "Scope used: ac.snag/snag (from the previous answer)", timeout=110000)
    page.get_by_role("button", name="New chat").click()
    wait_text(page, "Server: Any")
    page.get_by_role("link", name="Server search").click()
    page.wait_for_timeout(1500)
    page.get_by_role("button", name="Clear", exact=True).click()
