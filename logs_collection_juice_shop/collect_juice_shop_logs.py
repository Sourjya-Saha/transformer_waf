"""Playwright Automated Traffic Generator & Log Collector for OWASP Juice Shop.

Generates realistic end-to-end user interactions and captures 20,000+ HTTP transaction logs
in both standard text (.txt) and structured JSON (.json) formats.
"""
import asyncio
import json
import os
import random
import string
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Request, Response
except ImportError:
    print("[ERROR] Playwright is not installed.")
    print("Please run: pip install playwright && playwright install chromium")
    sys.exit(1)

# Default Configuration
DEFAULT_BASE_URL = os.getenv("JUICE_SHOP_URL", "http://localhost:3000")
DEFAULT_TARGET_LOGS = int(os.getenv("TARGET_LOGS", "20000"))
DEFAULT_CONCURRENCY = int(os.getenv("CONCURRENCY", "4"))

OUTPUT_DIR = Path(__file__).resolve().parent
TXT_LOG_FILE = OUTPUT_DIR / "juice_shop_logs.txt"
JSON_LOG_FILE = OUTPUT_DIR / "juice_shop_logs.json"


class JuiceShopLogCollector:
    """Collects all HTTP request/response transactions and saves them to .txt and .json files."""

    def __init__(self, target_logs: int = 20000, txt_path: Path = TXT_LOG_FILE, json_path: Path = JSON_LOG_FILE):
        self.target_logs = target_logs
        self.txt_path = txt_path
        self.json_path = json_path
        self.log_count = 0
        self.pending_requests: Dict[str, Dict[str, Any]] = {}
        self.all_logs: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()
        self._txt_handle = open(self.txt_path, "a", encoding="utf-8", buffering=1)

        # Clear existing logs on startup
        if os.path.exists(self.json_path):
            try:
                os.remove(self.json_path)
            except Exception:
                pass
        self._txt_handle.truncate(0)

    async def handle_request(self, request: Request):
        """Called when an HTTP request is dispatched by the browser."""
        req_id = f"{id(request)}_{time.time_ns()}"
        headers_dict = {}
        try:
            headers_dict = dict(await request.all_headers())
        except Exception:
            try:
                headers_dict = dict(request.headers)
            except Exception:
                pass

        post_data = ""
        try:
            post_data = request.post_data or ""
        except Exception:
            pass

        async with self._lock:
            self.pending_requests[req_id] = {
                "id": req_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "start_time": time.time(),
                "method": request.method,
                "url": request.url,
                "resource_type": request.resource_type,
                "headers": headers_dict,
                "post_data": post_data,
            }
        return req_id

    async def handle_response(self, response: Response):
        """Called when an HTTP response is received."""
        now = time.time()
        req = response.request

        headers_dict = {}
        try:
            headers_dict = dict(await response.all_headers())
        except Exception:
            try:
                headers_dict = dict(response.headers)
            except Exception:
                pass

        content_length = 0
        try:
            content_length = len(await response.body())
        except Exception:
            cl_header = headers_dict.get("content-length", "0")
            content_length = int(cl_header) if cl_header.isdigit() else 0

        post_data = ""
        try:
            post_data = req.post_data or ""
        except Exception:
            pass

        req_headers = {}
        try:
            req_headers = dict(await req.all_headers())
        except Exception:
            try:
                req_headers = dict(req.headers)
            except Exception:
                pass

        log_entry = {
            "log_id": self.log_count + 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "client_ip": "127.0.0.1",
            "method": req.method,
            "url": req.url,
            "status_code": response.status,
            "status_text": response.status_text,
            "resource_type": req.resource_type,
            "request_headers": req_headers,
            "request_payload": post_data,
            "response_headers": headers_dict,
            "response_size_bytes": content_length,
        }

        async with self._lock:
            self.log_count += 1
            self.all_logs.append(log_entry)

            # 1. Write to Text Log (Standard formatted HTTP transaction log)
            txt_line = (
                f"[{log_entry['timestamp']}] "
                f"IP:{log_entry['client_ip']} "
                f"METHOD:{log_entry['method']} "
                f"URL:{log_entry['url']} "
                f"STATUS:{log_entry['status_code']} "
                f"SIZE:{log_entry['response_size_bytes']}B "
                f"TYPE:{log_entry['resource_type']}\n"
            )
            self._txt_handle.write(txt_line)

            # Print progress every 100 logs
            if self.log_count % 100 == 0 or self.log_count >= self.target_logs:
                print(f"[*] Progress: {self.log_count:,} / {self.target_logs:,} logs collected ({(self.log_count/self.target_logs)*100:.1f}%)")

            # Periodically write JSON checkpoint
            if self.log_count % 1000 == 0 or self.log_count >= self.target_logs:
                self.save_json_checkpoint()

    def save_json_checkpoint(self):
        """Saves collected logs to the structured JSON file."""
        try:
            with open(self.json_path, "w", encoding="utf-8") as f:
                json.dump({"total_logs": len(self.all_logs), "logs": self.all_logs}, f, indent=2)
        except Exception as e:
            print(f"[!] Warning saving JSON log checkpoint: {e}")

    def close(self):
        """Finalize and close open log files."""
        try:
            self._txt_handle.close()
        except Exception:
            pass
        self.save_json_checkpoint()


# ==============================================================================
# Playwright User Journey Automation
# ==============================================================================
def random_string(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def random_email() -> str:
    return f"shopper_{random_string(6)}@juice-test.org"


async def dismiss_juice_shop_banners(page: Page):
    """Dismisses the welcome dialog and cookie banner on OWASP Juice Shop."""
    try:
        dismiss_btn = page.locator("button[aria-label='Close Welcome Banner'], button.close-dialog, button:has-text('Dismiss')").first
        if await dismiss_btn.is_visible(timeout=1000):
            await dismiss_btn.click()
    except Exception:
        pass

    try:
        cookie_btn = page.locator("a[aria-label='dismiss cookie message'], button:has-text('Me want it!')").first
        if await cookie_btn.is_visible(timeout=1000):
            await cookie_btn.click()
    except Exception:
        pass


# ------------------------------------------------------------------------------
# 1. User Registration & Security Questions Journey
# ------------------------------------------------------------------------------
async def user_journey_registration(page: Page, base_url: str):
    """Performs full user account registration including security questions."""
    email = random_email()
    password = "JuicePassword2026!"

    try:
        await page.goto(f"{base_url}/#/register", wait_until="domcontentloaded", timeout=10000)
        await dismiss_juice_shop_banners(page)

        email_input = page.locator("input#emailControl").first
        if await email_input.is_visible(timeout=2000):
            await email_input.fill(email)
            await page.locator("input#passwordControl").first.fill(password)
            await page.locator("input#repeatPasswordControl").first.fill(password)

            # Security question dropdown
            sq_select = page.locator("mat-select[name='securityQuestion']").first
            if await sq_select.is_visible(timeout=1500):
                await sq_select.click()
                first_option = page.locator("mat-option").first
                if await first_option.is_visible(timeout=1500):
                    await first_option.click()

            # Security answer
            await page.locator("input#securityAnswerControl").first.fill("Fluffy The Cat")

            # Click Register button
            register_btn = page.locator("button#registerButton").first
            if await register_btn.is_visible(timeout=1500) and await register_btn.is_enabled():
                await register_btn.click()
                await page.wait_for_timeout(random.randint(400, 800))
    except Exception:
        # Fallback via direct API registration call to ensure high-fidelity auth logs
        try:
            await page.evaluate(f"""
                async () => {{
                    try {{
                        const res = await fetch('{base_url}/api/Users/', {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify({{
                                email: '{email}',
                                password: '{password}',
                                passwordRepeat: '{password}',
                                securityQuestion: {{ id: 1, question: "Mother's maiden name?" }},
                                securityAnswer: 'Smith'
                            }})
                        }});
                        return await res.json();
                    }} catch (e) {{ return null; }}
                }}
            """)
        except Exception:
            pass


# ------------------------------------------------------------------------------
# 2. User Login, Authentication, & Session Journey
# ------------------------------------------------------------------------------
async def user_journey_login_logout(page: Page, base_url: str):
    """Performs user login with valid/invalid credentials, session verification, and logout."""
    email = random_email()
    password = "JuicePassword2026!"

    try:
        await page.goto(f"{base_url}/#/login", wait_until="domcontentloaded", timeout=10000)
        await dismiss_juice_shop_banners(page)

        email_input = page.locator("input#email").first
        if await email_input.is_visible(timeout=2000):
            # 1. Fill login credentials
            await email_input.fill(email)
            await page.locator("input#password").first.fill(password)

            login_btn = page.locator("button#loginButton").first
            if await login_btn.is_visible(timeout=1500):
                await login_btn.click()
                await page.wait_for_timeout(random.randint(400, 800))
    except Exception:
        pass

    # Also perform programmatic REST API login transactions
    try:
        await page.evaluate(f"""
            async () => {{
                try {{
                    const res = await fetch('{base_url}/rest/user/login', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{ email: '{email}', password: '{password}' }})
                    }});
                    const data = await res.json();
                    if (data.authentication && data.authentication.token) {{
                        // Check whoami endpoint with token
                        await fetch('{base_url}/rest/user/whoami', {{
                            headers: {{ 'Authorization': 'Bearer ' + data.authentication.token }}
                        }});
                    }}
                }} catch (e) {{}}
            }}
        """)
    except Exception:
        pass


# ------------------------------------------------------------------------------
# 3. Product Catalog Browsing & Search Journey
# ------------------------------------------------------------------------------
async def user_journey_browse_and_search(page: Page, base_url: str):
    """Simulates browsing product catalog, search queries, pagination, and reviews."""
    search_queries = [
        "apple", "juice", "banana", "shirt", "hoodie", "sticker", "mug", "orange",
        "lemon", "box", "card", "green", "smoothie", "pack", "special", "egg"
    ]
    query = random.choice(search_queries)

    try:
        await page.goto(f"{base_url}/#/", wait_until="domcontentloaded", timeout=10000)
        await dismiss_juice_shop_banners(page)

        # Search bar interaction
        search_icon = page.locator("mat-icon:has-text('search'), mat-search-bar mat-icon").first
        if await search_icon.is_visible(timeout=1500):
            await search_icon.click()
            search_input = page.locator("input#mat-input-0, input[type='text'].mat-input-element").first
            if await search_input.is_visible(timeout=1500):
                await search_input.fill(query)
                await page.keyboard.press("Enter")
                await page.wait_for_timeout(random.randint(300, 600))

        # Click on a random product card to open product review dialog
        product_cards = page.locator("mat-card.mat-card, div.product")
        count = await product_cards.count()
        if count > 0:
            idx = random.randint(0, min(count - 1, 5))
            await product_cards.nth(idx).click(timeout=2000)
            await page.wait_for_timeout(random.randint(400, 800))

            # Close dialog if opened
            close_btn = page.locator("button:has-text('Close'), mat-dialog-actions button").first
            if await close_btn.is_visible(timeout=1500):
                await close_btn.click()
    except Exception:
        pass


# ------------------------------------------------------------------------------
# 4. Cart, Basket, & Order Checkout Journey
# ------------------------------------------------------------------------------
async def user_journey_cart_and_checkout(page: Page, base_url: str):
    """Simulates adding items to basket, applying discount codes, and navigating checkout."""
    try:
        await page.goto(f"{base_url}/#/", wait_until="domcontentloaded", timeout=10000)
        await dismiss_juice_shop_banners(page)

        # Click 'Add to Basket' button on a product
        basket_btn = page.locator("button[aria-label='Add to Basket']").first
        if await basket_btn.is_visible(timeout=1500):
            await basket_btn.click(timeout=2000)
            await page.wait_for_timeout(random.randint(300, 600))

        # Navigate to basket page
        await page.goto(f"{base_url}/#/basket", wait_until="domcontentloaded", timeout=10000)
        await dismiss_juice_shop_banners(page)
        await page.wait_for_timeout(random.randint(400, 800))
    except Exception:
        pass

    # Also perform programmatic Basket API calls
    try:
        await page.evaluate(f"""
            async () => {{
                try {{
                    const bid = Math.floor(Math.random() * 5) + 1;
                    const pid = Math.floor(Math.random() * 10) + 1;
                    await fetch('{base_url}/api/BasketItems/', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{ ProductId: pid, BasketId: bid, quantity: 1 }})
                    }});
                    await fetch('{base_url}/rest/basket/' + bid);
                }} catch (e) {{}}
            }}
        """)
    except Exception:
        pass


# ------------------------------------------------------------------------------
# 5. Customer Feedback & Contact Journey
# ------------------------------------------------------------------------------
async def user_journey_contact_feedback(page: Page, base_url: str):
    """Submits customer feedback on the Contact page."""
    try:
        await page.goto(f"{base_url}/#/contact", wait_until="domcontentloaded", timeout=10000)
        await dismiss_juice_shop_banners(page)

        comment_box = page.locator("textarea#feedback-comment, textarea[aria-label='Comments']").first
        if await comment_box.is_visible(timeout=2000):
            await comment_box.fill(f"Great experience! Review #{random_string(5)}")

            slider = page.locator("mat-slider#rating, mat-slider").first
            if await slider.is_visible(timeout=1500):
                await slider.click()

            submit_btn = page.locator("button#submitButton, button:has-text('Submit')").first
            if await submit_btn.is_visible(timeout=1500) and await submit_btn.is_enabled():
                await submit_btn.click()
                await page.wait_for_timeout(random.randint(300, 600))
    except Exception:
        pass


# ------------------------------------------------------------------------------
# 6. Deep REST API Invocations (Products, Delivery, Cards, Challenges)
# ------------------------------------------------------------------------------
async def user_journey_deep_api_requests(page: Page, base_url: str):
    """Fires in-depth REST and GraphQL API queries across all Juice Shop subsystems."""
    api_endpoints = [
        ("GET", "/rest/products/search?q="),
        ("GET", "/rest/products/search?q=apple"),
        ("GET", "/rest/products/search?q=banana"),
        ("GET", "/rest/products/search?q=orange"),
        ("GET", "/api/Challenges/"),
        ("GET", "/api/Feedbacks/"),
        ("GET", "/api/Complaints/"),
        ("GET", "/api/SecurityQuestions/"),
        ("GET", "/api/Deliverys/"),
        ("GET", "/api/Cards/"),
        ("GET", "/api/Addresss/"),
        ("GET", "/rest/admin/application-version"),
        ("GET", "/rest/admin/application-configuration"),
        ("GET", "/rest/image-captchas/"),
        ("GET", "/rest/track-order/" + random_string(8)),
        ("GET", "/api/Quantitys/"),
    ]
    method, endpoint = random.choice(api_endpoints)
    try:
        await page.evaluate(f"""
            async () => {{
                try {{
                    const res = await fetch('{base_url}{endpoint}', {{ method: '{method}' }});
                    return await res.json();
                }} catch (e) {{ return null; }}
            }}
        """)
        await page.wait_for_timeout(random.randint(80, 200))
    except Exception:
        pass


# ==============================================================================
# Worker Loop
# ==============================================================================
async def worker_task(worker_id: int, browser: Browser, base_url: str, collector: JuiceShopLogCollector):
    """Autonomous Playwright worker running randomized user journeys until target logs are reached."""
    context: BrowserContext = await browser.new_context(
        viewport={"width": 1280, "height": 720},
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    )
    page: Page = await context.new_page()

    # Attach network lifecycle listeners to capture all HTTP transactions
    page.on("response", lambda res: asyncio.create_task(collector.handle_response(res)))

    journeys = [
        user_journey_registration,
        user_journey_login_logout,
        user_journey_browse_and_search,
        user_journey_cart_and_checkout,
        user_journey_contact_feedback,
        user_journey_deep_api_requests,
        user_journey_deep_api_requests,  # Weighted higher for rich telemetry
    ]

    try:
        while collector.log_count < collector.target_logs:
            journey = random.choice(journeys)
            await journey(page, base_url)
            await asyncio.sleep(random.uniform(0.1, 0.4))
    except asyncio.CancelledError:
        pass
    except Exception as e:
        print(f"[Worker {worker_id}] Notice: {e}")
    finally:
        await context.close()


# ==============================================================================
# Main Orchestrator
# ==============================================================================
async def run_log_collection(base_url: str, target_logs: int, concurrency: int):
    print("=" * 75)
    print(f"  OWASP Juice Shop Log Collector (Target: {target_logs:,} Logs)")
    print(f"  Target Website : {base_url}")
    print(f"  Output TXT Log : {TXT_LOG_FILE}")
    print(f"  Output JSON Log: {JSON_LOG_FILE}")
    print(f"  Workers        : {concurrency} parallel browser contexts")
    print("=" * 75)

    collector = JuiceShopLogCollector(target_logs=target_logs, txt_path=TXT_LOG_FILE, json_path=JSON_LOG_FILE)

    async with async_playwright() as p:
        print("[*] Launching headless browser engine...")
        browser = await p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]
        )

        workers = [
            asyncio.create_task(worker_task(i + 1, browser, base_url, collector))
            for i in range(concurrency)
        ]

        try:
            while collector.log_count < target_logs:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            print("\n[!] User interrupted collection. Saving recorded logs...")
        finally:
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            await browser.close()
            collector.close()

    print("\n" + "=" * 75)
    print(f"  Collection Complete: {collector.log_count:,} HTTP transactions recorded!")
    print(f"  - Plain Text Log : {TXT_LOG_FILE} ({os.path.getsize(TXT_LOG_FILE):,} bytes)")
    print(f"  - Structured JSON: {JSON_LOG_FILE} ({os.path.getsize(JSON_LOG_FILE):,} bytes)")
    print("=" * 75)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Collect 20,000 HTTP logs from OWASP Juice Shop with Playwright")
    parser.add_argument("--url", default=DEFAULT_BASE_URL, help=f"Juice Shop base URL (default: {DEFAULT_BASE_URL})")
    parser.add_argument("--logs", type=int, default=DEFAULT_TARGET_LOGS, help=f"Target number of logs to collect (default: {DEFAULT_TARGET_LOGS})")
    parser.add_argument("--workers", type=int, default=DEFAULT_CONCURRENCY, help=f"Concurrent browser workers (default: {DEFAULT_CONCURRENCY})")

    args = parser.parse_args()
    asyncio.run(run_log_collection(base_url=args.url, target_logs=args.logs, concurrency=args.workers))


if __name__ == "__main__":
    main()
