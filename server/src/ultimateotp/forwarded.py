# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Who the client really is behind a reverse proxy, and whether it is on the owner's LAN.

Same rule as UltimateTunes' `core/forwarded.py`: `ClientAddress` is the outermost middleware
and rewrites `scope["client"]`.

- The TCP peer is inside `UOTP_TRUSTED_PROXIES`: `X-Forwarded-For` is read from the right,
  skipping trusted proxies; the first other hop is the client. A hop that is not an IP address
  makes the client `unknown`, and so does a chain made only of trusted proxies (a proxy that
  replaced the header with its own peer must never be mistaken for a LAN client).
- Any other peer is the client. When it sends forwarding headers anyway, an unconfigured proxy
  stands in front: the request is marked and never counts as coming from the LAN.
"""

from starlette.types import ASGIApp, Receive, Scope, Send

from ultimateotp.netaddr import IpNetwork, in_networks, parse_ip

VIA_UNTRUSTED_PROXY = "ultimateotp.via_untrusted_proxy"
UNKNOWN_CLIENT = "unknown"
FORWARDING_HEADERS = frozenset(
    {b"forwarded", b"x-forwarded-for", b"x-forwarded-host", b"x-real-ip", b"cf-connecting-ip"}
)
MAX_HOPS = 32


def client_from_chain(hops: list[str], proxies: tuple[IpNetwork, ...]) -> str:
    for count, hop in enumerate(reversed(hops), start=1):
        address = parse_ip(hop)
        if address is None or count > MAX_HOPS:
            return UNKNOWN_CLIENT
        if not in_networks(str(address), proxies):
            return str(address)
    return UNKNOWN_CLIENT


def resolve(scope: Scope, proxies: tuple[IpNetwork, ...]) -> Scope:
    headers: list[tuple[bytes, bytes]] = scope.get("headers", [])
    peer = scope.get("client")
    host = peer[0] if peer else None
    if not in_networks(host, proxies):
        if any(name.lower() in FORWARDING_HEADERS for name, _ in headers):
            return {**scope, VIA_UNTRUSTED_PROXY: True}
        return scope
    values = [v.decode("latin-1") for k, v in headers if k.lower() == b"x-forwarded-for"]
    if not values:
        # The proxy itself (its own health checks).
        return scope
    hops = [hop.strip() for value in values for hop in value.split(",")]
    return {**scope, "client": (client_from_chain(hops, proxies), 0)}


def client_host(scope: Scope) -> str | None:
    peer = scope.get("client")
    return peer[0] if peer else None


def from_networks(
    scope: Scope, networks: tuple[IpNetwork, ...], denied: tuple[IpNetwork, ...] = ()
) -> bool:
    """The resolved client is inside `networks`, outside `denied`, and did not come through an
    untrusted proxy."""
    host = client_host(scope)
    return (
        not scope.get(VIA_UNTRUSTED_PROXY, False)
        and in_networks(host, networks)
        and not in_networks(host, denied)
    )


class ClientAddress:
    """Plain ASGI middleware: rewrites `scope["client"]` as described above."""

    def __init__(self, app: ASGIApp, proxies: tuple[IpNetwork, ...]) -> None:
        self._app = app
        self._proxies = proxies

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            scope = resolve(scope, self._proxies)
        await self._app(scope, receive, send)
