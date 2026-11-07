import atexit
import json
import os
import secrets
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

password = secrets.token_urlsafe(24)
temporary = tempfile.TemporaryDirectory()
server = subprocess.Popen(
    [".venv/bin/exchange", "serve", "--port", "8001"],
    env={
        **os.environ,
        "EXCHANGE_DATA_DIR": temporary.name,
        "EXCHANGE_DEMO_PASSWORD": password,
    },
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)


def cleanup():
    server.terminate()
    server.wait(timeout=10)
    temporary.cleanup()


atexit.register(cleanup)
for attempt in range(100):
    try:
        urllib.request.urlopen("http://127.0.0.1:8001/api/health", timeout=1)
        break
    except Exception:
        time.sleep(0.1)
else:
    raise RuntimeError("sandbox did not start")
Path(".local/screenshots").mkdir(parents=True, exist_ok=True)
errors = []
with sync_playwright() as p:
    browser = p.chromium.launch(
        executable_path="/usr/bin/chromium", headless=True, args=["--no-sandbox"]
    )
    page = browser.new_page(
        viewport={"width": 1440, "height": 1060}, device_scale_factor=1
    )
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.goto("http://127.0.0.1:8001")

    def login(officer):
        page.get_by_label("Demo officer").select_option(officer)
        page.get_by_label("Sandbox password").fill(password)
        page.get_by_role("button", name="Enter workspace").click()
        page.get_by_role("heading", name="A clearer path to settlement.").wait_for()

    login("seller-trader")
    page.screenshot(path=".local/screenshots/overview.png", full_page=True)
    page.get_by_role("button", name=__import__("re").compile("^Approvals")).click()
    page.locator(".inbox-card").first.click()
    page.get_by_role("button", name="Approve & sign").click()
    page.get_by_text("Approval signed and recorded.").wait_for()
    assert page.locator(".page-heading .pill").inner_text() == "Gaps Open"
    page.screenshot(path=".local/screenshots/trade.png", full_page=True)
    page.get_by_role("button", name="Sign out / switch demo officer").click()
    login("buyer-ops")
    page.get_by_role("button", name=__import__("re").compile("^Approvals")).click()
    page.locator(".inbox-card").first.click()
    page.get_by_role("heading", name="Kyc Release", exact=True).wait_for()
    page.get_by_role("button", name="Approve & sign").click()
    page.get_by_text("Approval signed and recorded.").wait_for()
    page.screenshot(path=".local/screenshots/approval.png", full_page=True)
    for officer in [
        "buyer-treasurer",
        "agent-officer",
        "agent-second",
        "agent-kyc",
        "agent-officer",
        "borrower-treasurer",
        "seller-signatory",
        "buyer-signatory",
        "agent-officer",
        "buyer-treasurer",
    ]:
        page.get_by_role("button", name="Sign out / switch demo officer").click()
        login(officer)
        page.get_by_role("button", name=__import__("re").compile("^Approvals")).click()
        page.locator(".inbox-card").first.click()
        page.get_by_role("button", name="Approve & sign").click()
        page.get_by_text("Approval signed and recorded.").wait_for()
    page.get_by_role("button", name="Sign out / switch demo officer").click()
    login("agent-officer")
    page.locator(".trades-table tbody tr").first.click()
    page.get_by_role("button", name="Simulate booked credit").click()
    page.locator(".task-line").filter(has_text="Settle Execute").click()
    page.get_by_role("button", name="Approve & sign").click()
    page.get_by_text("Approval signed and recorded.").wait_for()
    page.locator(".page-heading .pill").filter(has_text="Settled").wait_for()
    page.screenshot(path=".local/screenshots/settled.png", full_page=True)
    page.get_by_role("button", name="Audit log", exact=True).click()
    page.get_by_text("Audit chain verified").wait_for()
    page.get_by_role("button", name="Administration", exact=True).click()
    page.get_by_text("Development sandbox · Production startup disabled").wait_for()
    page.set_viewport_size({"width": 390, "height": 844})
    page.get_by_role("button", name="Overview", exact=True).click()
    page.screenshot(path=".local/screenshots/mobile.png", full_page=True)
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    browser.close()
assert not errors, errors
print(
    json.dumps(
        {
            "browser": "system Chromium",
            "passed": [
                "login",
                "dashboard",
                "seller proposal approval",
                "officer switch",
                "KYC release approval",
                "audit view",
                "admin view",
                "mobile viewport",
                "full assignment settled through browser approvals",
            ],
            "console_errors": errors,
        }
    )
)
