"""Centralized resolve-pin-and-gate egress guard (SSRF / DNS-rebinding defense).

Scope enforcement everywhere else in the harness is *lexical* — it matches hostnames and
literal CIDRs. That is not enough on its own:

* an attacker-controlled but in-scope hostname can resolve to ``169.254.169.254`` or a private
  address (classic SSRF-to-metadata), and
* it can *rebind* between the moment scope is checked and the moment the socket connects
  (TOCTOU / DNS rebinding), so validating the name string proves nothing about where the
  connection actually lands, and
* the destination can be smuggled past a naive check with an encoded IP literal
  (``2852039166``, ``0xA9FEA9FE``, ``[::ffff:169.254.169.254]`` all mean 169.254.169.254).

For the in-process HTTP path this module closes all three at the one place that matters — the
actual socket connect (the guarded connection resolves, validates, and pins in one step). The
external-CLI path (``run_recon``) cannot pin a socket it does not own, so it uses
:func:`resolve_and_validate` as a pre-flight check before spawning the binary — strong against a
statically-poisoned or internal-pointing name, with a documented residual TOCTOU because the CLI
re-resolves independently.

The controls:

1. :func:`normalize_host` canonicalizes integer/hex/IPv4-mapped-IPv6 encodings to a plain IP
   so a literal can never dodge the deny check.
2. :func:`validate_ip` rejects loopback, link-local, private, ULA, CGNAT, multicast,
   reserved, unspecified, and cloud-metadata addresses unless the operator explicitly opted
   into private ranges in the RoE.
3. :class:`GuardedHTTPConnection` / :class:`GuardedHTTPSConnection` resolve the host **once**,
   validate **every** returned address (deny-before-allow: one bad answer rejects the host),
   and connect to *that* validated address — so the IP that was checked is the IP that is
   used. There is no rebinding window.

Wire it in via :func:`guarded_handlers`, which returns urllib handlers bound to an
:class:`EgressPolicy`. ``HttpSession`` installs them for direct (non-proxied) traffic; when an
operator routes through Burp/a pivot the proxy owns egress and the lexical gate still applies.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import urllib.request
from dataclasses import dataclass

# Cloud metadata endpoints that are not otherwise caught by the range checks below.
_METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata.goog",
    "metadata.azure.internal",
}
# Exactly the SSRF-dangerous ranges. Enumerated explicitly rather than leaning on
# ``ipaddress.is_private``/``is_reserved`` because those also flag the RFC5737/RFC3849
# documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24, 2001:db8::/32) that are used
# as public-target stand-ins. Loopback (127/8, ::1) is intentionally omitted — see
# :func:`ip_is_forbidden`.
_FORBIDDEN_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),        # "this network" / unspecified source
    ipaddress.ip_network("10.0.0.0/8"),       # RFC1918 private
    ipaddress.ip_network("100.64.0.0/10"),    # RFC6598 CGNAT
    ipaddress.ip_network("169.254.0.0/16"),   # link-local incl. cloud metadata 169.254.169.254
    ipaddress.ip_network("172.16.0.0/12"),    # RFC1918 private
    ipaddress.ip_network("192.168.0.0/16"),   # RFC1918 private
    ipaddress.ip_network("224.0.0.0/4"),      # multicast
    ipaddress.ip_network("240.0.0.0/4"),      # reserved / future use (incl. 255.255.255.255)
    ipaddress.ip_network("::/128"),           # IPv6 unspecified
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique-local (ULA)
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
    ipaddress.ip_network("ff00::/8"),         # IPv6 multicast
]
_GLOBAL_DEFAULT_TIMEOUT = socket._GLOBAL_DEFAULT_TIMEOUT  # type: ignore[attr-defined]


@dataclass(frozen=True)
class EgressPolicy:
    """How strict the egress guard is. ``allow_private`` mirrors ``RoE.allow_private_ranges``."""

    allow_private: bool = False


def normalize_host(host: str) -> str:
    """Canonicalize a host: encoded IPv4/IPv6 literals collapse to a plain IP; names pass through.

    ``0xA9FEA9FE`` / ``2852039166`` / ``[::ffff:169.254.169.254]`` all become
    ``169.254.169.254`` so no encoding dodges :func:`validate_ip`. A real hostname is returned
    lower-cased and dot-stripped, unchanged otherwise.
    """
    h = (host or "").strip().lower().rstrip(".")
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    # Already a valid IP (this also handles IPv4-mapped IPv6 like ::ffff:a.b.c.d).
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        ip = None
    if ip is None:
        # Integer or hex encoding of an IPv4 address.
        value: int | None = None
        try:
            if h.startswith("0x"):
                value = int(h, 16)
            elif h.isdigit():
                value = int(h, 10)
        except ValueError:
            value = None
        if value is not None and 0 <= value <= 0xFFFF_FFFF:
            return str(ipaddress.ip_address(value))
        # Dotted octal/hex/shorthand IPv4 (e.g. 0251.0376.0251.0376, 0xa9.0xfe.0xa9.0xfe, 10.1)
        # that ipaddress rejects but inet_aton's legacy parser — and the resolver — accept. Only
        # attempt it for strings that are purely numeric/hex labels, so real hostnames pass through.
        if "." in h and all(c in "0123456789abcdefx." for c in h):
            try:
                return socket.inet_ntoa(socket.inet_aton(h))
            except OSError:
                pass
        return h
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        return str(mapped)
    return ip.compressed


def resolve_and_validate(host: str, policy: EgressPolicy | None = None) -> None:
    """Resolve ``host`` and raise if ANY resolved address is a forbidden destination.

    For the external-CLI path (nmap/httpx/nuclei/…) SecForge cannot pin the socket — the binary
    does its own DNS — so this is the strongest available guard: reject before spawning if the
    name resolves (now) to a private/metadata address. A residual TOCTOU remains (the CLI may
    re-resolve to a different answer), but a statically-poisoned or in-scope-but-internal name is
    caught here, closing the gap the lexical check alone leaves open. Unresolvable names are left
    for the tool to fail on (a resolution error is not a security bypass).
    """
    policy = policy or EgressPolicy()
    if policy.allow_private:
        return
    canonical = normalize_host(host)
    try:
        ipaddress.ip_address(canonical)
        infos = [(None, None, None, None, (canonical, 0))]  # already a literal IP
    except ValueError:
        try:
            infos = socket.getaddrinfo(canonical, None, type=socket.SOCK_STREAM)
        except OSError:
            return  # unresolvable — the external tool will fail; not a guard bypass
    for _family, _type, _proto, _canon, sockaddr in infos:
        validate_ip(sockaddr[0], policy)


def _as_v4(ip: ipaddress._BaseAddress) -> ipaddress._BaseAddress:
    """Unwrap an IPv4-mapped IPv6 address to its embedded IPv4 so range checks see the real IP."""
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped if mapped is not None else ip


def ip_is_forbidden(ip: ipaddress._BaseAddress) -> bool:
    """True when ``ip`` is in a range no authorized external target should ever live in.

    Loopback (127.0.0.0/8, ``::1``) is deliberately NOT forbidden: SecForge has always treated
    localhost as an explicitly-trusted target (``tools.base.LOCAL_HOSTS``, the defense-autopilot
    localhost attack flow), so blocking it by default would break local-lab testing. Every other
    internal range (link-local incl. cloud metadata, RFC1918 private, IPv6 ULA, RFC6598 CGNAT,
    multicast, unspecified, reserved) is forbidden unless the RoE opts into private ranges.
    """
    ip = _as_v4(ip)
    if ip.is_loopback:
        return False
    return any(ip in net for net in _FORBIDDEN_NETS if net.version == ip.version)


def validate_ip(ip_str: str, policy: EgressPolicy) -> None:
    """Raise :class:`PermissionError` if ``ip_str`` is a forbidden destination under ``policy``."""
    ip = ipaddress.ip_address(ip_str)
    if policy.allow_private:
        return
    if ip_is_forbidden(ip):
        raise PermissionError(
            f"egress to {ip_str} is blocked: private/loopback/link-local/metadata address "
            "(set RoE.allow_private_ranges to authorize internal testing)"
        )


def guard_host(host: str, policy: EgressPolicy | None = None) -> None:
    """Lexical pre-check: reject a host that *is* (or encodes) a forbidden IP literal or a
    metadata name. DNS names defer to connect-time resolution in the guarded connection."""
    policy = policy or EgressPolicy()
    canonical = normalize_host(host)
    if canonical in _METADATA_HOSTS and not policy.allow_private:
        raise PermissionError(f"egress to metadata host {canonical!r} is blocked")
    try:
        ipaddress.ip_address(canonical)
    except ValueError:
        return  # a hostname — validated when it resolves at connect time
    validate_ip(canonical, policy)


def _guarded_create_connection(
    host: str,
    port: int,
    timeout: object,
    source_address: tuple[str, int] | None,
    policy: EgressPolicy,
) -> socket.socket:
    """Resolve ``host`` once, validate every answer, and connect to a validated address.

    Deny-before-allow: if *any* resolved address is forbidden the whole host is rejected, so a
    rebinding resolver that returns one public and one internal answer cannot slip through. The
    address that passed validation is the address connected to — no second lookup, no window.
    """
    if port in (None, 0):
        port = 80
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not infos:
        raise OSError(f"could not resolve {host!r}")
    for _family, _type, _proto, _canon, sockaddr in infos:
        validate_ip(sockaddr[0], policy)
    last_error: Exception | None = None
    for family, sock_type, proto, _canon, sockaddr in infos:
        sock = socket.socket(family, sock_type, proto)
        try:
            if timeout is not _GLOBAL_DEFAULT_TIMEOUT and timeout is not None:
                sock.settimeout(float(timeout))  # type: ignore[arg-type]
            if source_address:
                sock.bind(source_address)
            sock.connect(sockaddr)
            return sock
        except OSError as exc:  # try the next validated address
            last_error = exc
            sock.close()
    raise last_error or OSError(f"could not connect to {host!r}")


class GuardedHTTPConnection(http.client.HTTPConnection):
    """An ``HTTPConnection`` that resolves+validates+pins its destination at connect time."""

    _egress_policy: EgressPolicy = EgressPolicy()

    def connect(self) -> None:  # noqa: D102 - overrides stdlib
        self.sock = _guarded_create_connection(
            self.host, self.port, self.timeout, self.source_address, self._egress_policy
        )
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if self._tunnel_host:
            self._tunnel()


class GuardedHTTPSConnection(http.client.HTTPSConnection):
    """An ``HTTPSConnection`` variant of :class:`GuardedHTTPConnection`.

    The pinned raw socket is TLS-wrapped with ``server_hostname`` = the original hostname, so
    SNI and certificate hostname verification are unaffected by the IP pinning.
    """

    _egress_policy: EgressPolicy = EgressPolicy()

    def connect(self) -> None:  # noqa: D102 - overrides stdlib
        self.sock = _guarded_create_connection(
            self.host, self.port, self.timeout, self.source_address, self._egress_policy
        )
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        server_hostname = self.host
        if self._tunnel_host:
            self._tunnel()
            server_hostname = self._tunnel_host
        self.sock = self._context.wrap_socket(self.sock, server_hostname=server_hostname)


def guarded_handlers(
    policy: EgressPolicy,
) -> tuple[urllib.request.HTTPHandler, urllib.request.HTTPSHandler]:
    """Return urllib HTTP/HTTPS handlers whose connections are guarded by ``policy``.

    ``build_opener`` prefers these over the default handlers, so every request through the
    resulting opener resolves, validates, and pins its destination.
    """
    http_conn = type("_BoundHTTPConn", (GuardedHTTPConnection,), {"_egress_policy": policy})
    https_conn = type("_BoundHTTPSConn", (GuardedHTTPSConnection,), {"_egress_policy": policy})

    class _GuardedHTTPHandler(urllib.request.HTTPHandler):
        def http_open(self, req: urllib.request.Request):  # type: ignore[override]
            return self.do_open(http_conn, req)

    class _GuardedHTTPSHandler(urllib.request.HTTPSHandler):
        def https_open(self, req: urllib.request.Request):  # type: ignore[override]
            return self.do_open(
                https_conn, req, context=self._context, check_hostname=self._check_hostname
            )

    return _GuardedHTTPHandler(), _GuardedHTTPSHandler()
