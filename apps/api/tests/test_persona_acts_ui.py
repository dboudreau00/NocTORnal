"""The console's half of the persona act queue (A collector process,
2026-10-02).

Pure: no database. A persona act's route answers 202 with the act while the
collector has not run it; `actCall` follows it to the outcome, so every
call site gets the body or the route's own refusal as before, and an act
that outlasts the console's patience is answered as queued, never as a
failure. The Feeds pane lists the caller's acts with a Cancel on a pending
one. The functions run under Node over the collection foundation's stub
DOM.
"""
from __future__ import annotations

import re

import pytest

from test_collection_ui_foundation import _fn, _run
from test_ui_copy_no_dashes import NODE, _html, _js

needs_node = pytest.mark.skipif(not NODE, reason="Node is not installed here")

#: Every console call that makes a persona act goes through actCall.
ACT_PATHS = ("'/collection/telegram/chats', { method: 'POST'",
             "+ '/membership'", "+ '/member',", "+ '/persona'", "+ '/join',",
             "'/collection/sources/' + s.id + '/run'")


def test_every_persona_act_the_console_asks_for_goes_through_act_call():
    js = _js()
    for path in ACT_PATHS:
        at = js.index(path)
        call = js.rindex("(", 0, at)
        name = re.search(r"(\w+)\($", js[call - 12:call + 1])
        assert name and name.group(1) == "actCall", (path, js[call - 40:at])


def test_the_acts_list_is_on_the_feeds_pane_and_loaded_with_it():
    html = _html()
    for ident in ("src-acts", "src-acts-empty"):
        assert html.count(f'id="{ident}"') == 1, ident
    assert html.index('id="src-personas"') < html.index('id="src-acts"') \
        < html.index('id="src-auth"')
    assert "loadPersonaActs();" in _fn("loadSources")
    assert "'/collection/acts?limit=25'" in _fn("loadPersonaActs")


@needs_node
def test_act_call_passes_a_finished_answer_through_and_follows_a_queued_one(tmp_path):
    got = _run(["actCall"], r"""
    globalThis.setTimeout = (f) => f();
    globalThis.apiAnswer = () => ({ member: true, notice: 'now' });
    const direct = await actCall('/collection/telegram/chats/s1/membership', {});
    let n = 0;
    globalThis.apiAnswer = (path) => {
      n += 1;
      if (n === 1) return { queued: true, act: { id: 'a1' }, notice: 'queued' };
      if (n === 2) return { act: { status: 'RUNNING' }, body: null, problem: null };
      return { act: { status: 'DONE' }, body: { member: false, notice: 'done' },
               problem: null };
    };
    const followed = await actCall('/collection/telegram/chats/s1/membership', {});
    globalThis.apiAnswer = (path) => (path.startsWith('/collection/acts/')
      ? { act: { status: 'REFUSED' }, body: null,
          problem: { status: 409, title: 'Conflict', detail: 'burnt' } }
      : { queued: true, act: { id: 'a2' } });
    let refused = null;
    try { await actCall('/collection/telegram/chats/s1/join', {}); }
    catch (e) { refused = e.status; }
    console.log(JSON.stringify({ direct, followed, refused, calls }));
    """, tmp_path, consts=["ACT_PATIENCE_MS", "ACT_QUEUED_TEXT"])
    assert got["direct"] == {"member": True, "notice": "now"}
    assert got["followed"] == {"member": False, "notice": "done"}
    assert got["refused"] == 409
    polled = [c["path"] for c in got["calls"] if c["path"].startswith("/collection/acts/")]
    assert polled[:2] == ["/collection/acts/a1", "/collection/acts/a1"]


@needs_node
def test_an_act_that_outlasts_the_consoles_patience_is_answered_as_queued(tmp_path):
    got = _run(["actCall"], r"""
    let clock = 0;
    globalThis.Date = { now: () => clock };
    globalThis.setTimeout = (f) => { clock += 60000; f(); };
    globalThis.apiAnswer = (path) => (path.startsWith('/collection/acts/')
      ? { act: { status: 'PENDING' }, body: null, problem: null }
      : { queued: true, act: { id: 'a3' } });
    const out = await actCall('/collection/sources/s1/run', {});
    console.log(JSON.stringify(out));
    """, tmp_path, consts=["ACT_PATIENCE_MS", "ACT_QUEUED_TEXT"])
    assert got["queued"] is True and "Persona acts" in got["notice"]


@needs_node
def test_an_act_row_says_what_and_how_it_ended_and_a_pending_one_can_be_cancelled(
        tmp_path):
    got = _run(["personaActRow"], r"""
    globalThis.loadPersonaActs = () => { calls.push({ reload: 'acts' }); };
    const done = personaActRow({ id: 'a1', what: 'Join a Telegram chat', status: 'DONE',
      requested_at: 'r', started_at: 's', finished_at: 'f', outcome: 'joined' });
    const pending = personaActRow({ id: 'a2', what: 'Poll a source a persona reads',
      status: 'PENDING', requested_at: 'r', outcome: null });
    const button = all(pending, (x) => x.tag === 'button')[0];
    await button.listeners.click();
    console.log(JSON.stringify({ done: text(done), doneChips: chips(done),
      doneButtons: buttons(done), pendingChips: chips(pending), calls }));
    """, tmp_path)
    assert "Join a Telegram chat" in got["done"] and "joined" in got["done"]
    assert got["doneChips"] == ["chip ok:DONE"] and got["doneButtons"] == []
    assert got["pendingChips"] == ["chip warn:PENDING"]
    sent = [c for c in got["calls"] if c.get("path")]
    assert sent == [{"path": "/collection/acts/a2/cancel",
                     "opts": {"method": "POST", "json": {}}}]
    assert {"reload": "acts"} in got["calls"]


def test_the_acts_help_text_names_the_operators_time_limit():
    """An act not started in time is not run, and the time is the
    operator's to set (NOCTORNAL_ACT_TTL_SECONDS, one minute to an hour):
    the help text must not promise a flat fifteen (2026-10-03)."""
    html = re.sub(r"\s+", " ", _html())
    block = html[html.index("Persona acts</h2>"):][:900]
    assert "fifteen minutes, unless your operator set another limit" in block
    assert "within fifteen minutes" not in block
