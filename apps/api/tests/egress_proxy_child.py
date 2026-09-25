"""The real egress proxy in a process of its own, for
test_egress_proxy_contract_pg.py (S2, 2026-09-24).

Not a test module and not shipped: the contract cases must count every name
the CLIENT process hands its resolver, so the proxy cannot share that
process. This child runs the unmodified EgressProxy with three test seams,
all read from files in the control directory given on the command line:

- names.json: the names the proxy's resolver answers, to loopback origins
  (egress_policy.resolve_and_pin calls socket.getaddrinfo, patched here);
- 127.0.0.0/8 is public here, the way test_collection_ssrf_rebinding.py
  stands loopback in for the internet (the classifier seam);
- refuse: when present, every authorisation is refused with the code it
  holds, which is how the runner arranges `refusing(code)`.

It prints "LISTENING <port>" once and serves until the file "stop" appears.
"""
from __future__ import annotations

import asyncio
import json
import socket
import sys
from pathlib import Path

CONTROL = Path(sys.argv[1])

from noctornal_api import egress_authz, egress_policy  # noqa: E402
from noctornal_api.egress_proxy import EgressProxy, ProxyConfig  # noqa: E402

_real_getaddrinfo = socket.getaddrinfo
_real_is_blocked = egress_policy.is_blocked
_real_authorise = egress_authz.authorise


def _names() -> dict:
    try:
        return json.loads((CONTROL / "names.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def getaddrinfo(host, port, *args, **kwargs):
    address = _names().get(host)
    if address is None:
        if host in ("localhost", "127.0.0.1"):
            return _real_getaddrinfo(host, port, *args, **kwargs)
        raise socket.gaierror(socket.EAI_NONAME, "not found")
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]


def is_blocked(address):
    unwrapped = getattr(address, "ipv4_mapped", None) or address
    if unwrapped.version == 4 and str(unwrapped).startswith("127."):
        return False
    return _real_is_blocked(address)


def authorise(conn, claim, host, port, **kwargs):
    refuse = CONTROL / "refuse"
    if refuse.exists():
        raise egress_authz.Refused(refuse.read_text(encoding="utf-8").strip())
    return _real_authorise(conn, claim, host, port, **kwargs)


socket.getaddrinfo = getaddrinfo
egress_policy.is_blocked = is_blocked
egress_authz.authorise = authorise


async def main() -> None:
    config = ProxyConfig.from_env()
    config.listen_port = 0
    proxy = EgressProxy(config)
    _host, port = await proxy.start()
    print(f"LISTENING {port}", flush=True)
    while not (CONTROL / "stop").exists():
        await asyncio.sleep(0.1)
    await proxy.stop()


if __name__ == "__main__":
    asyncio.run(main())
