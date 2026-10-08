"""The live socket says "ready" only once the hub is listening (2026-10-08).

docs/17 "the socket says ready early": `live()` sent `{"type": "ready"}` as
soon as `_Hub.subscribe()` returned, and `subscribe()` returned as soon as it
had started the listener task, not when that task's `LISTEN` had run. A write
made between "ready" and the registration reached nobody, the console had
already turned its dot green on "ready", and the socket tests covered the gap
with `time.sleep(1.0)`. Now `subscribe()` waits for the registration, a hub
that cannot register ends the socket with 1013 instead of saying ready, and
the sleeps are gone.

No database: the listener is a stand-in whose `LISTEN` can be held, so the gap
is made on purpose and the result is the same on a quiet machine and a loaded
one.
"""
from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from uuid import uuid4

import pytest

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PEER = "203.0.113.80"      # TEST-NET, never a real peer
LIVE = "/api/v1/live"


class _Listener:
    """A LISTEN connection whose `LISTEN` waits on `gate`, and which hears
    nothing."""

    def __init__(self, log: list[str], gate: threading.Event):
        self.log, self.gate = log, gate
        self.closed = False

    def execute(self, sql, *args):
        if sql.startswith("LISTEN"):
            assert self.gate.wait(20), "the test never released the LISTEN"
            self.log.append("LISTEN")
        elif sql.startswith("UNLISTEN"):
            self.log.append("UNLISTEN")

    def notifies(self, timeout=None):
        time.sleep(min(timeout or 0.05, 0.05))
        return iter(())

    def close(self):
        self.closed = True


@pytest.fixture
def live(monkeypatch):
    from noctornal_api.http.routers import live as module
    monkeypatch.setattr(module, "_PING_SECONDS", 0.2)
    monkeypatch.setattr(module, "_POLL_SECONDS", 0.05)
    # A hub per test: its lock belongs to the loop of the test that used it.
    monkeypatch.setattr(module, "_hub", module._Hub())
    return module


def _held_listener(live, monkeypatch):
    """Patch the hub's connection so `LISTEN` is held; returns (log, gate,
    listeners)."""
    log: list[str] = []
    gate = threading.Event()
    made: list[_Listener] = []

    def connect():
        made.append(_Listener(log, gate))
        return made[-1]

    monkeypatch.setattr(live, "connect_request", connect)
    return log, gate, made


async def _turns(n: int = 20, pause: float = 0.01) -> None:
    for _ in range(n):
        await asyncio.sleep(pause)


# --- the hub ---------------------------------------------------------------

def test_subscribe_returns_only_after_the_listen_is_registered(live, monkeypatch):
    log, gate, _made = _held_listener(live, monkeypatch)

    async def go():
        waiting = asyncio.create_task(live._hub.subscribe())
        await _turns()
        assert not waiting.done(), (
            "subscribe() returned before the LISTEN ran: a socket would say "
            "ready over a hub that is not yet listening")
        assert log == []
        gate.set()
        queue = await asyncio.wait_for(waiting, 10)
        assert log == ["LISTEN"]
        assert live._hub.count == 1
        await live._hub.unsubscribe(queue)

    asyncio.run(go())
    assert live._hub.count == 0


def test_a_second_subscriber_shares_the_one_listener_and_is_not_held_up(live, monkeypatch):
    log, gate, made = _held_listener(live, monkeypatch)
    gate.set()

    async def go():
        first = await live._hub.subscribe()
        second = await asyncio.wait_for(live._hub.subscribe(), 1)
        assert len(made) == 1, "one LISTEN connection serves every socket"
        assert live._hub.count == 2
        await live._hub.unsubscribe(first)
        await live._hub.unsubscribe(second)

    asyncio.run(go())
    assert log.count("LISTEN") == 1


def test_two_subscribers_that_arrive_together_both_wait_for_the_one_registration(
        live, monkeypatch):
    log, gate, made = _held_listener(live, monkeypatch)

    async def go():
        a = asyncio.create_task(live._hub.subscribe())
        b = asyncio.create_task(live._hub.subscribe())
        await _turns()
        assert not a.done() and not b.done()
        gate.set()
        queues = await asyncio.wait_for(asyncio.gather(a, b), 10)
        assert len(made) == 1 and log == ["LISTEN"]
        for queue in queues:
            await live._hub.unsubscribe(queue)

    asyncio.run(go())


def test_a_listener_that_cannot_connect_is_refused_and_leaves_no_subscriber(live, monkeypatch):
    def refuse():
        raise OSError("the database is down")

    monkeypatch.setattr(live, "connect_request", refuse)

    async def go():
        with pytest.raises(live.ListenerUnavailable):
            await asyncio.wait_for(live._hub.subscribe(), 10)
        assert live._hub.count == 0
        # And the next try starts a run of its own rather than joining a dead one.
        with pytest.raises(live.ListenerUnavailable):
            await asyncio.wait_for(live._hub.subscribe(), 10)

    asyncio.run(go())


def test_a_listener_that_never_registers_is_given_up_on(live, monkeypatch):
    log, gate, _made = _held_listener(live, monkeypatch)
    monkeypatch.setattr(live, "connect_timeout_seconds", lambda: 0)
    monkeypatch.setattr(live, "_LISTEN_GRACE_SECONDS", 0.2)

    async def go():
        with pytest.raises(live.ListenerUnavailable):
            await asyncio.wait_for(live._hub.subscribe(), 10)
        assert live._hub.count == 0
        gate.set()          # let the held thread go before the loop closes

    asyncio.run(go())


def test_a_socket_that_goes_while_waiting_leaves_no_subscriber_and_no_listener(
        live, monkeypatch):
    log, gate, made = _held_listener(live, monkeypatch)

    async def go():
        waiting = asyncio.create_task(live._hub.subscribe())
        await _turns()
        waiting.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiting
        assert live._hub.count == 0
        gate.set()
        for _ in range(200):
            if made and made[0].closed:
                break
            await asyncio.sleep(0.02)
        assert made and made[0].closed, "the listener outlived its last subscriber"

    asyncio.run(go())


def test_a_subscriber_that_arrives_while_the_last_run_winds_down_does_not_keep_it_alive(
        live, monkeypatch):
    """One stop flag per run. The hub had one for all of them: the last
    subscriber leaving set it, and a subscriber arriving before the old run
    had looked at it cleared it again, so the old run went on listening beside
    the new one and every event was fanned out twice. The old run was only
    ended by the timeout `unsubscribe` waits under, which cancels it."""
    log, gate, made = _held_listener(live, monkeypatch)
    gate.set()
    monkeypatch.setattr(live, "_POLL_SECONDS", 0.4)

    class Slow(_Listener):
        def notifies(self, timeout=None):
            time.sleep(0.4)
            return iter(())

    monkeypatch.setattr(live, "connect_request",
                        lambda: made.append(Slow(log, gate)) or made[-1])

    async def go():
        first = await live._hub.subscribe()
        leaving = asyncio.create_task(live._hub.unsubscribe(first))
        await asyncio.sleep(0.05)               # the old run is inside its poll
        second = await live._hub.subscribe()    # a run of its own
        assert len(made) == 2
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 1.4            # the old code ended it at 2.0
        while loop.time() < deadline and not made[0].closed:
            await asyncio.sleep(0.02)
        stopped = made[0].closed
        await leaving
        assert stopped, "the old run kept listening beside the new one"
        assert made[1].closed is False
        await live._hub.unsubscribe(second)

    asyncio.run(go())


# --- the socket ------------------------------------------------------------

def _scope() -> dict:
    return {
        "type": "websocket", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "scheme": "ws", "path": LIVE, "raw_path": LIVE.encode(), "root_path": "",
        "query_string": b"", "headers": [(b"host", b"testserver")],
        "client": (PEER, 40000), "server": ("testserver", 80), "subprotocols": [],
        "state": {},
    }


def _drive(monkeypatch, live, *, after_ready_leave: threading.Event | None = None):
    """The real endpoint on the real app, with the handshake's database check
    replaced by an answer. Returns (messages, start, finish): `start()` begins
    the run and `finish()` awaits it."""
    from noctornal_api.http.app import create_app

    async def authenticated(_ws, _ip):
        return uuid4(), None, None, None

    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter

    monkeypatch.setattr(live, "_handshake", authenticated)
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    sent: list[dict] = []
    leave = asyncio.Event()
    inbound = iter([{"type": "websocket.connect"}])

    async def receive():
        try:
            return next(inbound)
        except StopIteration:
            await leave.wait()
            return {"type": "websocket.disconnect", "code": 1000}

    async def send(message):
        sent.append(message)

    def start():
        return asyncio.create_task(app(_scope(), receive, send))

    return sent, start, leave


def test_ready_is_not_sent_until_the_hub_is_listening(live, monkeypatch):
    log, gate, _made = _held_listener(live, monkeypatch)
    sent, start, leave = _drive(monkeypatch, live)

    async def go():
        run = start()
        await _turns(30)
        kinds = [m["type"] for m in sent]
        assert "websocket.accept" in kinds
        assert not any(m["type"] == "websocket.send" for m in sent), (
            "the socket said ready while the hub's LISTEN was still pending")
        gate.set()
        for _ in range(300):
            if any(m["type"] == "websocket.send" for m in sent):
                break
            await asyncio.sleep(0.02)
        ready = [m for m in sent if m["type"] == "websocket.send"]
        assert ready and json.loads(ready[0]["text"])["type"] == "ready", sent
        assert log == ["LISTEN"], "ready came before the LISTEN"
        leave.set()
        await asyncio.wait_for(run, 10)

    asyncio.run(go())


def test_a_hub_that_cannot_listen_closes_the_socket_instead_of_saying_ready(live, monkeypatch):
    def refuse():
        raise OSError("the database is down")

    monkeypatch.setattr(live, "connect_request", refuse)
    sent, start, leave = _drive(monkeypatch, live)

    async def go():
        await asyncio.wait_for(start(), 15)

    asyncio.run(go())
    kinds = [m["type"] for m in sent]
    assert "websocket.send" not in kinds, sent
    closed = [m for m in sent if m["type"] == "websocket.close"]
    assert closed and closed[0]["code"] == 1013, sent
    assert closed[0]["reason"] == "live updates are unavailable"
    assert live._hub.count == 0


def test_the_socket_tests_no_longer_wait_for_the_listener():
    """The three that covered the gap with a one-second sleep after "ready"
    (test_g45_live_labels_pg.py) rely on the order now, as a client does."""
    from pathlib import Path
    text = Path(__file__).with_name("test_g45_live_labels_pg.py").read_text(encoding="utf-8")
    assert "time.sleep(" not in text
    assert "LISTEN registers after" not in text
