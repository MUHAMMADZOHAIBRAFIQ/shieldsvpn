"""A loopback stand-in for the Paddle Billing API (the subset pqvpn/portal/payments.py uses)."""

from __future__ import annotations

import json
import re
import secrets
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000000Z", time.gmtime(ts))


class FakePaddle:
    API_KEY = "pdl_sdbx_apikey_test_0123456789"

    def __init__(self):
        self.customers: dict[str, dict] = {}
        self.transactions: dict[str, dict] = {}
        self.subscriptions: dict[str, dict] = {}
        self.prices: dict[str, dict] = {}
        self.refuse_intervals: set[str] = set()  # POST /prices fails for these billing intervals (error paths)
        self.requests: list[tuple[str, str]] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, status: int, data):
                body = json.dumps({"data": data} if status < 400 else {"error": data}).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _route(self, method: str):
                fake.requests.append((method, self.path))
                if self.headers.get("Authorization") != f"Bearer {FakePaddle.API_KEY}":
                    return self._reply(403, {"code": "forbidden", "detail": "bad API key"})
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else {}
                url = urllib.parse.urlsplit(self.path)
                q = urllib.parse.parse_qs(url.query)
                if method == "GET" and url.path == "/customers":
                    email = q.get("email", [""])[0]
                    return self._reply(200, [c for c in fake.customers.values() if c["email"] == email])
                if method == "POST" and url.path == "/customers":
                    cid = "ctm_" + secrets.token_hex(13)
                    fake.customers[cid] = {"id": cid, "email": body["email"]}
                    return self._reply(201, fake.customers[cid])
                if method == "POST" and url.path == "/prices":
                    interval = body["billing_cycle"]["interval"]
                    if interval in fake.refuse_intervals:
                        return self._reply(400, {"code": "invalid_field", "detail": f"{interval} refused by the test"})
                    pid = "pri_" + secrets.token_hex(13)
                    fake.prices[pid] = {"id": pid, "status": "active", "product_id": body["product_id"],
                                        "description": body["description"], "billing_cycle": body["billing_cycle"],
                                        "unit_price": body["unit_price"], "quantity": body.get("quantity")}
                    return self._reply(201, fake.prices[pid])
                m = re.fullmatch(r"/prices/(pri_[a-z0-9]+)", url.path)
                if method == "PATCH" and m:
                    item = fake.prices.get(m.group(1))
                    if item is None:
                        return self._reply(404, {"code": "not_found", "detail": url.path})
                    item.update(body)
                    return self._reply(200, item)
                if method == "POST" and url.path == "/transactions":
                    if any(fake.prices.get(i["price_id"], {}).get("status") == "archived" for i in body["items"]):
                        return self._reply(400, {"code": "price_archived", "detail": "price is archived"})
                    tid = "txn_" + secrets.token_hex(13)
                    fake.transactions[tid] = {
                        "id": tid, "status": "ready", "customer_id": body["customer_id"],
                        "custom_data": body.get("custom_data"), "currency_code": "USD", "subscription_id": None,
                        "items": [{"price": {"id": i["price_id"]}, "quantity": i["quantity"]} for i in body["items"]],
                        "details": {"totals": {"grand_total": "500"}}}
                    return self._reply(201, fake.transactions[tid])
                m = re.fullmatch(r"/(transactions|subscriptions)/([a-z]+_[a-z0-9]+)", url.path)
                if method == "GET" and m:
                    table = fake.transactions if m.group(1) == "transactions" else fake.subscriptions
                    item = table.get(m.group(2))
                    return self._reply(200, item) if item else self._reply(404, {"code": "not_found", "detail": ""})
                m = re.fullmatch(r"/customers/(ctm_[a-z0-9]+)/portal-sessions", url.path)
                if method == "POST" and m:
                    return self._reply(201, {"urls": {"general": {
                        "overview": f"https://customer-portal.paddle.com/cpl_{m.group(1)[4:]}"}}})
                return self._reply(404, {"code": "not_found", "detail": url.path})

            def do_GET(self):
                self._route("GET")

            def do_POST(self):
                self._route("POST")

            def do_PATCH(self):
                self._route("PATCH")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def pay(self, txn_id: str, days: int = 30, status: str = "active", custom_data: dict | None = None) -> str:
        """What happens at Paddle when the buyer completes the checkout: the transaction is paid and a
        subscription starts (it inherits the transaction's custom_data)."""
        txn = self.transactions[txn_id]
        sid = "sub_" + secrets.token_hex(13)
        now = time.time()
        self.subscriptions[sid] = {
            "id": sid, "status": status, "customer_id": txn["customer_id"],
            "custom_data": custom_data if custom_data is not None else txn["custom_data"],
            "current_billing_period": {"starts_at": iso(now), "ends_at": iso(now + days * 86400)},
            "canceled_at": None}
        txn.update(status="completed", subscription_id=sid)
        return sid

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
