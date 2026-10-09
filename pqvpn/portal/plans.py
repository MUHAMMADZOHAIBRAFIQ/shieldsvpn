"""Service plans (Free / Premium) and the DNS servers each plan gets.

The VPN server pushes DNS servers to a client in the handshake.  With the
portal, the servers come from (first match wins):

  1. the account's own DNS override (set by an admin on the user's page),
  2. the DNS chosen for the account's *effective* plan in Admin -> Settings,
  3. ``[tunnel] dns`` in server.toml.

Premium can carry an expiry date; after it the account is treated as Free
automatically (no job needs to run).  Plan and DNS changes take effect at the
user's next connection.
"""

from __future__ import annotations

import ipaddress
import time

PLANS = {"free": "Free", "premium": "Premium"}
MAX_DNS = 4

# Well-known public resolvers.  "Filtering" ones block domains server-side.
DNS_PRESETS: dict[str, tuple[str, list[str]]] = {
    "default": ("Server default (server.toml)", []),
    "cloudflare": ("Cloudflare: fast, privacy-first", ["1.1.1.1", "1.0.0.1"]),
    "cloudflare-security": ("Cloudflare Security: blocks malware", ["1.1.1.2", "1.0.0.2"]),
    "cloudflare-family": ("Cloudflare Family: blocks malware + adult content", ["1.1.1.3", "1.0.0.3"]),
    "quad9": ("Quad9: blocks malware and phishing", ["9.9.9.9", "149.112.112.112"]),
    "adguard": ("AdGuard: blocks ads, trackers and malware", ["94.140.14.14", "94.140.15.15"]),
    "adguard-family": ("AdGuard Family: ads + trackers + adult content", ["94.140.14.15", "94.140.15.16"]),
    "google": ("Google Public DNS", ["8.8.8.8", "8.8.4.4"]),
    "custom": ("Custom servers", []),
}

DEFAULT_SETTINGS = {"dns_free_preset": "default", "dns_free_custom": "",
                    "dns_premium_preset": "adguard", "dns_premium_custom": ""}


def parse_dns(text: str) -> list[str]:
    """'1.1.1.1, 2606:4700::1111' -> canonical list.  Raises ValueError with a readable reason."""
    out = []
    for part in text.replace(";", ",").replace(" ", ",").split(","):
        if not part:
            continue
        try:
            ip = str(ipaddress.ip_address(part))
        except ValueError:
            raise ValueError(f"{part!r} is not an IP address") from None
        if ip not in out:
            out.append(ip)
    if len(out) > MAX_DNS:
        raise ValueError(f"at most {MAX_DNS} DNS servers")
    return out


def effective_plan(user: dict, now: float | None = None) -> str:
    if (user.get("plan") or "free") != "premium":
        return "free"
    expires = user.get("plan_expires")
    if expires and expires <= (time.time() if now is None else now):
        return "free"
    return "premium"


def plan_dns(settings: dict, plan: str) -> list[str]:
    preset = settings.get(f"dns_{plan}_preset") or DEFAULT_SETTINGS[f"dns_{plan}_preset"]
    if preset == "custom":
        try:
            return parse_dns(settings.get(f"dns_{plan}_custom", ""))
        except ValueError:
            return []
    return list(DNS_PRESETS.get(preset, ("", []))[1])


def dns_for(user: dict, settings: dict, now: float | None = None) -> list[str]:
    """DNS servers to push to this account ([] = fall back to server.toml)."""
    if user.get("custom_dns"):
        try:
            return parse_dns(user["custom_dns"])
        except ValueError:
            pass
    return plan_dns(settings, effective_plan(user, now))


def describe_dns(settings: dict, plan: str) -> str:
    preset = settings.get(f"dns_{plan}_preset") or DEFAULT_SETTINGS[f"dns_{plan}_preset"]
    label = DNS_PRESETS.get(preset, ("Unknown", []))[0].split(":")[0]
    servers = plan_dns(settings, plan)
    return f"{label} ({', '.join(servers)})" if servers else label
