"""Operating-system network configuration with automatic rollback.

Every change registers its inverse; ``teardown()`` undoes them in reverse
order so a stopped VPN leaves the routing table exactly as it found it.

Full-tunnel mode uses the 0.0.0.0/1 + 128.0.0.0/1 technique (more specific
than, so overriding, the default route without deleting it) plus a pinned
host route to the VPN server through the original gateway, so the encrypted
UDP packets themselves never loop into the tunnel.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import shutil
import subprocess
import sys
import time

log = logging.getLogger("pqvpn.net")

FULL_V4 = ["0.0.0.0/1", "128.0.0.0/1"]
FULL_V6 = ["::/1", "8000::/1"]


class NetConfig:
    def __init__(self, ifname: str, if_index: int | None = None, dry_run: bool = False):
        self.ifname, self.if_index, self.dry_run = ifname, if_index, dry_run
        self._undo: list[list[str]] = []
        self.linux = sys.platform.startswith("linux")
        self.windows = sys.platform == "win32"

    # -------------------------------------------------------------- plumbing
    def _run(self, argv: list[str], check: bool = True) -> str:
        log.debug("exec: %s", " ".join(argv))
        if self.dry_run:
            return ""
        p = subprocess.run(argv, capture_output=True, text=True)
        if p.returncode != 0 and check:
            raise RuntimeError(f"{' '.join(argv)} failed: {(p.stderr or p.stdout).strip()}")
        return p.stdout

    def _do(self, argv: list[str], undo: list[str] | None = None) -> None:
        # A freshly created Wintun adapter can take a moment to accept netsh.
        attempts = 5 if self.windows else 1
        for i in range(attempts):
            try:
                self._run(argv)
                break
            except RuntimeError:
                if i == attempts - 1:
                    raise
                time.sleep(1)
        if undo:
            self._undo.append(undo)

    def teardown(self) -> None:
        while self._undo:
            argv = self._undo.pop()
            try:
                self._run(argv, check=False)
            except Exception as exc:  # never let cleanup abort cleanup
                log.warning("cleanup step failed: %s", exc)

    # -------------------------------------------------------------- interface
    def configure_interface(self, addresses: list[str], mtu: int) -> None:
        ifaces = [ipaddress.ip_interface(a) for a in addresses]
        if self.linux:
            for i in ifaces:
                self._do(["ip", "addr", "add", str(i), "dev", self.ifname])
            self._do(["ip", "link", "set", "dev", self.ifname, "mtu", str(mtu), "up"])
        elif self.windows:
            name = f"name={self.ifname}"
            for i in ifaces:
                if i.version == 4:
                    self._do(["netsh", "interface", "ipv4", "set", "address", name, "source=static",
                              f"address={i.ip}", f"mask={i.netmask}"])
                else:
                    self._do(["netsh", "interface", "ipv6", "add", "address", f"interface={self.ifname}",
                              f"address={i}", "store=active"])
            for fam in ("ipv4", "ipv6"):
                self._run(["netsh", "interface", fam, "set", "subinterface", self.ifname,
                           f"mtu={mtu}", "store=active"], check=False)
            self._run(["netsh", "interface", "ipv4", "set", "interface", self.ifname, "metric=5"], check=False)
        else:
            raise NotImplementedError(sys.platform)

    def add_routes(self, nets: list[str]) -> None:
        for n in nets:
            net = ipaddress.ip_network(n, strict=False)
            if self.linux:
                fam = "-6" if net.version == 6 else "-4"
                self._do(["ip", fam, "route", "replace", str(net), "dev", self.ifname],
                         ["ip", fam, "route", "del", str(net), "dev", self.ifname])
            elif self.windows:
                fam = "ipv6" if net.version == 6 else "ipv4"
                nh = "::" if net.version == 6 else "0.0.0.0"
                args = [f"prefix={net}", f"interface={self.ifname}", f"nexthop={nh}"]
                self._do(["netsh", "interface", fam, "add", "route", *args, "metric=1", "store=active"],
                         ["netsh", "interface", fam, "delete", "route", *args, "store=active"])

    def pin_endpoint(self, server_ip: str) -> None:
        """Route the VPN server itself via the current (pre-VPN) path."""
        ip = ipaddress.ip_address(server_ip)
        if ip.is_loopback:
            return
        if self.linux:
            fam = "-6" if ip.version == 6 else "-4"
            out = self._run(["ip", "-j", fam, "route", "get", str(ip)])
            if self.dry_run:
                return
            route = json.loads(out)[0]
            host = f"{ip}/{ip.max_prefixlen}"
            argv = ["ip", fam, "route", "replace", host]
            if route.get("gateway"):
                argv += ["via", route["gateway"]]
            argv += ["dev", route["dev"]]
            self._do(argv, ["ip", fam, "route", "del", host])
        elif self.windows:
            if ip.version != 4:
                log.warning("IPv6 endpoint pinning not implemented on Windows; use split tunnel")
                return
            nh, ifidx = _windows_best_route_v4(ip)
            args = [f"prefix={ip}/32", f"interface={ifidx}", f"nexthop={nh}"]
            self._do(["netsh", "interface", "ipv4", "add", "route", *args, "metric=1", "store=active"],
                     ["netsh", "interface", "ipv4", "delete", "route", *args, "store=active"])

    def set_dns(self, servers: list[str]) -> None:
        if not servers:
            return
        if self.linux:
            if not shutil.which("resolvectl"):
                log.warning("resolvectl not found; DNS servers %s not applied", servers)
                return
            self._do(["resolvectl", "dns", self.ifname, *servers], ["resolvectl", "revert", self.ifname])
            self._run(["resolvectl", "domain", self.ifname, "~."], check=False)
        elif self.windows:
            v4 = [s for s in servers if ipaddress.ip_address(s).version == 4]
            for i, s in enumerate(v4):
                if i == 0:
                    self._run(["netsh", "interface", "ipv4", "set", "dnsservers", f"name={self.ifname}",
                               "source=static", f"address={s}", "register=none", "validate=no"])
                else:
                    self._run(["netsh", "interface", "ipv4", "add", "dnsservers", f"name={self.ifname}",
                               f"address={s}", f"index={i + 1}", "validate=no"])

    # -------------------------------------------------------------- server NAT (Linux)
    def enable_forwarding_nat(self, subnets: list[str], out_iface: str) -> None:
        if not self.linux:
            log.warning("NAT/forwarding automation is Linux-only; configure ICS/RRAS manually on Windows")
            return
        self._run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        if any(ipaddress.ip_network(s, strict=False).version == 6 for s in subnets):
            self._run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"])
        for s in subnets:
            net = ipaddress.ip_network(s, strict=False)
            ipt = "ip6tables" if net.version == 6 else "iptables"
            rules = [
                ["-t", "nat", "POSTROUTING", "-s", str(net), "-o", out_iface, "-j", "MASQUERADE"],
                ["-t", "filter", "FORWARD", "-i", self.ifname, "-o", out_iface, "-j", "ACCEPT"],
                ["-t", "filter", "FORWARD", "-i", out_iface, "-o", self.ifname,
                 "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
                # Clamp TCP MSS so inner TCP never needs PMTU discovery across the tunnel.
                ["-t", "mangle", "FORWARD", "-o", self.ifname, "-p", "tcp",
                 "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
                ["-t", "mangle", "FORWARD", "-i", self.ifname, "-p", "tcp",
                 "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
            ]
            for r in rules:
                table, chain, spec = r[:2], r[2], r[3:]
                self._do([ipt, *table, "-I", chain, *spec], [ipt, *table, "-D", chain, *spec])


def _windows_best_route_v4(ip: ipaddress.IPv4Address) -> tuple[str, int]:
    import ctypes
    from ctypes import wintypes

    class MIB_IPFORWARDROW(ctypes.Structure):
        _fields_ = [(n, wintypes.DWORD) for n in (
            "dest", "mask", "policy", "next_hop", "if_index", "type", "proto", "age",
            "next_hop_as", "metric1", "metric2", "metric3", "metric4", "metric5")]

    row = MIB_IPFORWARDROW()
    rc = ctypes.WinDLL("iphlpapi").GetBestRoute(int.from_bytes(ip.packed, "little"), 0, ctypes.byref(row))
    if rc != 0:
        raise RuntimeError(f"GetBestRoute({ip}) failed: {rc}")
    return str(ipaddress.IPv4Address(row.next_hop.to_bytes(4, "little"))), row.if_index
