"""A change hint must not be lost while the stream is idle-pinging (g45 verification, 2026-10-03).

`_stream` waits on the socket and on the hub queue at once, with a timeout
that is the ping interval. When the timeout fires neither is done and the
loop takes its idle branch: a session check on a worker thread, then a ping
on the socket. Both yield to the event loop. A hint that arrives in that
window completes the queue getter task while nobody is looking, and the loop
top used to replace a done getter with a fresh one without reading it, so
the hint was thrown away and the console missed a refetch it had been told
to make. In production the window is one session check per 25 seconds, so
the loss was rare and invisible; under a 0.2 s ping and a loaded machine the
socket test failed one run in two.

This file needs no database: the stream is driven with a socket that
delivers the hint at the one moment that matters, so the race is made on
purpose rather than hoped for, and the result is the same on a quiet machine
and a loaded one.
"""
from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest


class _Socket:
    """A socket whose first ping is the moment a hint arrives: the hint is
    put on the queue from inside `send_json`, and the event loop is then let
    run until the getter task has finished, which is the window the old loop
    top mishandled."""

    def __init__(self, queue: asyncio.Queue, payload: dict, *, pings_allowed: int):
        self.queue = queue
        self.payload = payload
        self.pings_allowed = pings_allowed
        self.sent: list[dict] = []
        self.closed: dict | None = None
        self._leave = asyncio.Event()

    async def receive(self) -> dict:
        await self._leave.wait()
        return {"type": "websocket.disconnect", "code": 1000}

    async def send_json(self, message: dict) -> None:
        self.sent.append(message)
        if message["type"] == "ping":
            if len([m for m in self.sent if m["type"] == "ping"]) == 1:
                self.queue.put_nowait(self.payload)
                # Several turns, so the getter task has certainly run to
                # completion before the loop returns to its top.
                for _ in range(5):
                    await asyncio.sleep(0)
            if len([m for m in self.sent if m["type"] == "ping"]) >= self.pings_allowed:
                self._leave.set()
        elif message["type"] == "change":
            self._leave.set()

    async def close(self, **kwargs) -> None:
        self.closed = kwargs


@pytest.fixture
def live(monkeypatch):
    from noctornal_api.http.routers import live as module
    monkeypatch.setattr(module, "_PING_SECONDS", 0.05)
    return module


def _run(live, payload: dict, user_id, *, pings_allowed: int = 6):
    async def go():
        queue: asyncio.Queue = asyncio.Queue()
        ws = _Socket(queue, payload, pings_allowed=pings_allowed)
        await asyncio.wait_for(
            live._stream(ws, queue, user_id, None, None, token=None), timeout=20)
        return ws

    return asyncio.run(go())


def test_a_hint_that_arrives_during_the_idle_ping_is_delivered(live):
    user_id = uuid4()
    ws = _run(live, {"kind": "notification", "recipient_id": str(user_id)}, user_id)
    assert {"type": "change", "kind": "notification"} in ws.sent, (
        "the hint that arrived while the loop was pinging was discarded; "
        f"the socket sent {ws.sent}")
    # And it came straight after the ping it arrived during, not a ping
    # interval later (which would mean it waited for a second getter).
    assert [m["type"] for m in ws.sent][:2] == ["ping", "change"]


def test_a_hint_for_someone_else_is_still_dropped_in_the_same_window(live):
    """The fix reads a finished getter; it must not make the loop deliver
    what `_relevant` would have refused."""
    user_id = uuid4()
    ws = _run(live, {"kind": "notification", "recipient_id": str(uuid4())}, user_id,
              pings_allowed=3)
    assert not [m for m in ws.sent if m["type"] == "change"]
