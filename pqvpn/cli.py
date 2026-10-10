"""Command-line interface:  python -m pqvpn <command> ..."""

from __future__ import annotations

import argparse
import asyncio
import base64
import getpass
import ipaddress
import logging
import os
import shutil
import sys

from . import __version__, pki
from .config import ConfigError, load_client, load_server
from .crypto import ossl
from .crypto.suites import DEFAULT_SUITES, SIG_ALGS, SUITES, sig_alg_by_name


def _passphrase(args, confirm: bool) -> bytes | None:
    if getattr(args, "passphrase_file", None):
        with open(args.passphrase_file, "rb") as f:
            return f.read().strip() or None
    if getattr(args, "no_passphrase", False) or not sys.stdin.isatty():
        return None
    pw = getpass.getpass("CA key passphrase (empty = unencrypted): ").encode()
    if pw and confirm and getpass.getpass("Repeat passphrase: ").encode() != pw:
        raise SystemExit("passphrases do not match")
    return pw or None


def _load_ca(ca_dir: str, args) -> tuple[pki.Certificate, ossl.PKey]:
    cert = pki.Certificate.load(os.path.join(ca_dir, "ca.crt"))
    key_path = os.path.join(ca_dir, "ca.key")
    try:
        key = pki.read_private_key(key_path, None if not getattr(args, "passphrase_file", None)
                                   else _passphrase(args, False))
    except ossl.OpenSSLError:
        key = pki.read_private_key(key_path, _passphrase(args, False))
    if cert.key_alg.public_bytes(key) != cert.public_key:
        raise SystemExit("ca.key does not match ca.crt")
    return cert, key


def _issue(ca_cert, ca_key, *, role, name, addresses, alg, days, out_dir, basename, pubkey=None):
    alg = sig_alg_by_name(alg)
    os.makedirs(out_dir, exist_ok=True)
    if pubkey:
        pub = ossl.public_from_pem(open(pubkey, "rb").read())
        if not pub.is_a(alg.name):
            raise SystemExit(f"{pubkey} is not an {alg.name} public key")
        public = alg.public_bytes(pub)
        key = None
    else:
        key = alg.generate()
        public = alg.public_bytes(key)
    cert = pki.issue(role=role, subject=name, key_alg=alg, public_key=public, addresses=addresses,
                     days=days, issuer_key=ca_key, issuer_alg=ca_cert.key_alg,
                     issuer_public=ca_cert.public_key)
    pki.write_file(os.path.join(out_dir, f"{basename}.crt"), cert.to_pem())
    if key is not None:
        pki.write_private_key(os.path.join(out_dir, f"{basename}.key"), key)
    return cert


# ---------------------------------------------------------------- commands

def cmd_algorithms(args) -> int:
    print(f"pqvpn {__version__} on {ossl.version_string()}\n")
    print("Cipher suites (id, name, default preference marked *):")
    for s in SUITES.values():
        mark = "*" if s.name in DEFAULT_SUITES else " "
        print(f"  {mark} 0x{s.id:04x}  {s.name}\n            {s.description}")
    print("\nSignature algorithms (id, name, public key / signature bytes):")
    for a in SIG_ALGS.values():
        print(f"    0x{a.id:04x}  {a.name:<20} {a.family:<8} pk {a.pub_len:>5}  sig {a.sig_len:>6}")
    return 0


def cmd_ca_init(args) -> int:
    os.makedirs(args.out, exist_ok=True)
    for f in ("ca.key", "ca.crt"):
        if os.path.exists(os.path.join(args.out, f)) and not args.force:
            raise SystemExit(f"{os.path.join(args.out, f)} exists (use --force to overwrite)")
    alg = sig_alg_by_name(args.alg)
    pw = _passphrase(args, True)
    print(f"Generating {alg.name} root CA key...")
    key = alg.generate()
    cert = pki.self_sign_ca(args.name, key, alg, args.days)
    pki.write_private_key(os.path.join(args.out, "ca.key"), key, pw)
    pki.write_file(os.path.join(args.out, "ca.crt"), cert.to_pem())
    print(cert.describe())
    if not pw:
        print("\nWARNING: ca.key is NOT encrypted. Keep it offline (e.g. on removable media).")
    return 0


def cmd_issue(args) -> int:
    ca_cert, ca_key = _load_ca(args.ca, args)
    role = pki.ROLE_BY_NAME[args.role]
    if role == pki.ROLE_CLIENT and not args.address:
        raise SystemExit("client certificates need --address (e.g. 10.66.0.2/32)")
    basename = args.basename or args.name.replace(" ", "_")
    cert = _issue(ca_cert, ca_key, role=role, name=args.name, addresses=args.address or [],
                  alg=args.alg, days=args.days, out_dir=args.out, basename=basename, pubkey=args.pubkey)
    shutil.copyfile(os.path.join(args.ca, "ca.crt"), os.path.join(args.out, "ca.crt"))
    print(cert.describe())
    return 0


def cmd_genkey(args) -> int:
    alg = sig_alg_by_name(args.alg)
    key = alg.generate()
    pki.write_private_key(args.out + ".key", key)
    with open(args.out + ".pub", "wb") as f:
        f.write(ossl.public_to_pem(key))
    print(f"wrote {args.out}.key (keep secret) and {args.out}.pub (send to the CA operator)")
    return 0


def cmd_show(args) -> int:
    print(pki.Certificate.load(args.file).describe())
    return 0


def cmd_genpsk(args) -> int:
    print(base64.b64encode(os.urandom(32)).decode())
    return 0


SERVER_TOML = """\
# pqvpn server configuration
[server]
listen = "0.0.0.0:{port}"
certificate = "server.crt"
private_key = "server.key"
ca = ["ca.crt"]

[tunnel]
interface = "pqvpn0"
mtu = 1420
# Tunnel address comes from the server certificate ({srv_addr}).
dns = ["1.1.1.1", "9.9.9.9"]          # pushed to clients
push_routes = ["{subnet}"]            # split-tunnel routes pushed to clients
nat_interface = ""                    # e.g. "eth0" to give clients Internet access (Linux)

[crypto]
suites = {suites}
peer_signature_algorithms = ["ML-DSA-65", "ML-DSA-87"]
ca_signature_algorithms = ["{ca_alg}"]
rekey_interval = 120
{psk_line}
[security]
revoked_serials = []
max_peers = 1024
cookie_threshold = 64
handshake_rate_per_ip = 5
"""

CLIENT_TOML = """\
# pqvpn client configuration for {name}
[client]
server = "{endpoint}"
server_name = "{server_name}"
certificate = "{base}.crt"
private_key = "{base}.key"
ca = ["ca.crt"]

[tunnel]
interface = "pqvpn0"
mtu = 1420
full_tunnel = false        # true = send ALL traffic through the VPN
routes = []                # empty = use routes pushed by the server
use_server_dns = true
persistent_keepalive = 25  # keeps NAT mappings alive

[crypto]
suites = {suites}
peer_signature_algorithms = ["ML-DSA-65", "ML-DSA-87"]
ca_signature_algorithms = ["{ca_alg}"]
rekey_interval = 120
{psk_line}"""


def cmd_quickstart(args) -> int:
    out = args.out
    if os.path.exists(out) and os.listdir(out) and not args.force:
        raise SystemExit(f"{out} is not empty (use --force)")
    net = ipaddress.ip_network(args.subnet, strict=True)
    hosts = net.hosts()
    srv_ip = next(hosts)
    clients = [c.strip() for c in args.clients.split(",") if c.strip()]
    ca_alg = sig_alg_by_name(args.ca_alg)
    suites = "[" + ", ".join(f'"{s}"' for s in DEFAULT_SUITES) + "]"

    ca_dir = os.path.join(out, "ca")
    os.makedirs(ca_dir, exist_ok=True)
    print(f"[1/3] Root CA: {ca_alg.name} (hash-based, FIPS 205)")
    ca_key = ca_alg.generate()
    ca_cert = pki.self_sign_ca(f"{args.server_name} Root CA", ca_key, ca_alg, 3650)
    pki.write_private_key(os.path.join(ca_dir, "ca.key"), ca_key, _passphrase(args, True))
    pki.write_file(os.path.join(ca_dir, "ca.crt"), ca_cert.to_pem())

    psk_line = ""
    psk = None
    if args.psk:
        psk = base64.b64encode(os.urandom(32)).decode()
        psk_line = 'psk_file = "psk.key"\n'

    def bundle(d: str) -> None:
        shutil.copyfile(os.path.join(ca_dir, "ca.crt"), os.path.join(d, "ca.crt"))
        if psk:
            pki.write_file(os.path.join(d, "psk.key"), psk + "\n")

    print(f"[2/3] Server certificate: {args.server_name} ({args.alg}), tunnel {srv_ip}/{net.prefixlen}")
    sdir = os.path.join(out, "server")
    _issue(ca_cert, ca_key, role=pki.ROLE_SERVER, name=args.server_name,
           addresses=[f"{srv_ip}/{net.prefixlen}"], alg=args.alg, days=args.days, out_dir=sdir,
           basename="server")
    bundle(sdir)
    port = args.endpoint.rsplit(":", 1)[1]
    pki.write_file(os.path.join(sdir, "server.toml"), SERVER_TOML.format(
        port=port, srv_addr=f"{srv_ip}/{net.prefixlen}", subnet=net, suites=suites,
        ca_alg=ca_alg.name, psk_line=psk_line))

    print(f"[3/3] Client certificates: {', '.join(clients)}")
    for name in clients:
        ip = next(hosts)
        cdir = os.path.join(out, "clients", name)
        _issue(ca_cert, ca_key, role=pki.ROLE_CLIENT, name=name, addresses=[f"{ip}/32"], alg=args.alg,
               days=args.days, out_dir=cdir, basename=name)
        bundle(cdir)
        pki.write_file(os.path.join(cdir, "client.toml"), CLIENT_TOML.format(
            name=name, endpoint=args.endpoint, server_name=args.server_name, base=name, suites=suites,
            ca_alg=ca_alg.name, psk_line=psk_line))
        print(f"      {name:<16} {ip}/32  -> {cdir}")
    print(f"""
Done. Layout:
  {ca_dir}/        ROOT CA -- move ca.key OFFLINE; needed only to issue/renew
  {sdir}/    copy to the server, then:  sudo python -m pqvpn server -c server.toml
  {os.path.join(out, 'clients')}/<name>/  give each user their folder:  python -m pqvpn client -c client.toml
""")
    return 0


def cmd_server(args) -> int:
    from .runner import run_server
    try:
        cfg = load_server(args.config)
    except ConfigError as exc:
        raise SystemExit(f"config error: {exc}")
    asyncio.run(run_server(cfg))
    return 0


def cmd_client(args) -> int:
    from .runner import run_client
    try:
        cfg = load_client(args.config)
    except ConfigError as exc:
        raise SystemExit(f"config error: {exc}")
    asyncio.run(run_client(cfg))
    return 0


def cmd_portal_init(args) -> int:
    from .portal.service import portal_init
    os.makedirs(args.data, exist_ok=True)
    password = portal_init(args.data, server_name=args.server_name, endpoint=args.endpoint, subnet=args.subnet,
                           admin=args.admin, listen=args.listen or ["127.0.0.1:8800"],
                           public_url=args.public_url or f"http://{(args.listen or ['127.0.0.1:8800'])[0]}/",
                           issuer=args.issuer, psk=args.psk, nat=args.nat_interface, ca_alg=args.ca_alg)
    print(f"""Portal created in {args.data}
  CA              ca/ca.crt (+ ca.key, used by the portal to issue profiles)
  VPN server      sudo python -m pqvpn server -c {os.path.join(args.data, 'server.toml')}
  Web portal      python -m pqvpn portal -c {os.path.join(args.data, 'portal.toml')}

First administrator:  {args.admin}
One-time password:    {password}
(you must choose a new password at first sign-in)""")
    return 0


def cmd_portal(args) -> int:
    from .config import load_portal
    from .portal.web import run_portal
    try:
        cfg = load_portal(args.config)
    except ConfigError as exc:
        raise SystemExit(f"config error: {exc}")
    run_portal(cfg)
    return 0


def cmd_app(args) -> int:
    from .app import install_shortcut, main
    if args.install_shortcut:
        for path in install_shortcut(args.config):
            print(f"created {path}")
        return 0
    return main(args.config, autoconnect=args.connect)


def cmd_tray(args) -> int:
    if sys.platform != "win32":
        raise SystemExit("the tray app is Windows-only; use `pqvpn client` elsewhere")
    from . import winui
    if args.install_shortcut:
        for path in winui.install_shortcut(args.config):
            print(f"created {path}")
        return 0
    return winui.main(args.config, autoconnect=not args.no_connect, replace=args.replace)


def cmd_selftest(args) -> int:
    from .runner import selftest
    return 0 if asyncio.run(selftest()) else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="pqvpn", description="Post-quantum, crypto-agile VPN "
                                "(ML-KEM + ECDH hybrid key exchange, ML-DSA / SLH-DSA authentication)")
    p.add_argument("-v", "--verbose", action="count", default=0)
    p.add_argument("--version", action="version", version=f"pqvpn {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("algorithms", help="list supported suites and signature algorithms").set_defaults(fn=cmd_algorithms)
    sub.add_parser("selftest", help="run an in-process handshake + data test for every suite").set_defaults(fn=cmd_selftest)
    sub.add_parser("genpsk", help="print a random 32-byte pre-shared key (base64)").set_defaults(fn=cmd_genpsk)

    q = sub.add_parser("quickstart", help="create a CA, server and client bundles with configs")
    q.add_argument("--out", default="vpn-pki")
    q.add_argument("--server-name", required=True, help="server identity, e.g. vpn.example.com")
    q.add_argument("--endpoint", required=True, help="address clients connect to, host:port")
    q.add_argument("--clients", required=True, help="comma-separated client names")
    q.add_argument("--subnet", default="10.66.0.0/24")
    q.add_argument("--ca-alg", default="SLH-DSA-SHA2-192s")
    q.add_argument("--alg", default="ML-DSA-65")
    q.add_argument("--days", type=float, default=365)
    q.add_argument("--psk", action="store_true", help="also generate a shared PSK (defence in depth)")
    q.add_argument("--passphrase-file")
    q.add_argument("--no-passphrase", action="store_true")
    q.add_argument("--force", action="store_true")
    q.set_defaults(fn=cmd_quickstart)

    c = sub.add_parser("ca-init", help="create a root CA")
    c.add_argument("--out", required=True)
    c.add_argument("--name", required=True)
    c.add_argument("--alg", default="SLH-DSA-SHA2-192s")
    c.add_argument("--days", type=float, default=3650)
    c.add_argument("--passphrase-file")
    c.add_argument("--no-passphrase", action="store_true")
    c.add_argument("--force", action="store_true")
    c.set_defaults(fn=cmd_ca_init)

    i = sub.add_parser("issue", help="issue a server or client certificate")
    i.add_argument("--ca", required=True, help="CA directory (ca.crt + ca.key)")
    i.add_argument("--role", required=True, choices=["server", "client"])
    i.add_argument("--name", required=True)
    i.add_argument("--address", action="append", help="tunnel address CIDR (repeatable)")
    i.add_argument("--alg", default="ML-DSA-65")
    i.add_argument("--days", type=float, default=365)
    i.add_argument("--out", required=True)
    i.add_argument("--basename")
    i.add_argument("--pubkey", help="sign an existing public key (from `genkey`) instead of generating one")
    i.add_argument("--passphrase-file")
    i.set_defaults(fn=cmd_issue)

    g = sub.add_parser("genkey", help="generate a device key pair locally (CSR-less enrolment)")
    g.add_argument("--alg", default="ML-DSA-65")
    g.add_argument("--out", required=True, help="path prefix; writes PREFIX.key and PREFIX.pub")
    g.set_defaults(fn=cmd_genkey)

    s = sub.add_parser("show", help="print a certificate")
    s.add_argument("file")
    s.set_defaults(fn=cmd_show)

    for name, fn in (("server", cmd_server), ("client", cmd_client)):
        r = sub.add_parser(name, help=f"run the VPN {name}")
        r.add_argument("-c", "--config", required=True)
        r.set_defaults(fn=fn)

    pi = sub.add_parser("portal-init", help="set up CA, VPN server and web portal with a first admin account")
    pi.add_argument("--data", required=True, help="data directory (local filesystem), e.g. /var/lib/pqvpn")
    pi.add_argument("--server-name", required=True)
    pi.add_argument("--endpoint", required=True, help="address VPN clients connect to, host:port")
    pi.add_argument("--subnet", default="10.66.0.0/24")
    pi.add_argument("--admin", default="admin")
    pi.add_argument("--listen", action="append", help="portal listen address host:port (repeatable)")
    pi.add_argument("--public-url", default="")
    pi.add_argument("--issuer", default="ShieldsVPN")
    pi.add_argument("--psk", action="store_true")
    pi.add_argument("--nat-interface", default="")
    pi.add_argument("--ca-alg", default="SLH-DSA-SHA2-192s")
    pi.set_defaults(fn=cmd_portal_init)

    po = sub.add_parser("portal", help="run the web login / administration portal")
    po.add_argument("-c", "--config", required=True)
    po.set_defaults(fn=cmd_portal)

    ap = sub.add_parser("app", help="ShieldsVPN desktop app: a simple 'Tap to Connect' window")
    ap.add_argument("-c", "--config", required=True)
    ap.add_argument("--connect", action="store_true", help="connect automatically on launch")
    ap.add_argument("--install-shortcut", action="store_true", help="create a Desktop/Start-menu shortcut")
    ap.set_defaults(fn=cmd_app)

    tr = sub.add_parser("tray", help="Windows taskbar app: shield icon, notifications, connect/disconnect")
    tr.add_argument("-c", "--config", required=True)
    tr.add_argument("--no-connect", action="store_true", help="start disconnected")
    tr.add_argument("--install-shortcut", action="store_true", help="create Desktop/Start-menu shortcuts")
    tr.add_argument("--replace", action="store_true", help="cleanly stop a running instance and start this one")
    tr.set_defaults(fn=cmd_tray)

    args = p.parse_args(argv)
    level = logging.WARNING if args.cmd in ("selftest",) and not args.verbose else \
        logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    try:
        return args.fn(args)
    except (pki.CertError, ossl.OpenSSLError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
