"""The console's Telegram lines, as it ships them (roadmap F5.2 and F5.3,
2026-09-24).

Pure: no database. The markup is read from the shipped index.html; the
functions marked `needs_node` run under Node over the collection
foundation's stub DOM (test_collection_ui_foundation) and are judged by what they
draw and what they send.
"""
from __future__ import annotations

import re

import pytest

from test_collection_ui_foundation import STUBS as FOUNDATION_STUBS
from test_collection_ui_foundation import _const, _fn, _run
from test_ui_copy_no_dashes import NODE, _html, _js

needs_node = pytest.mark.skipif(not NODE, reason="Node is not installed here")

TG_IDS = ("src-tg", "src-tg-empty", "src-tg-off", "src-tg-box", "src-tg-form",
          "stg-persona", "stg-ref", "stg-name", "stg-class", "stg-public",
          "stg-member", "stg-every", "stg-btn", "stg-error", "stg-ok",
          "sp-tg-device", "sp-tg-model", "sp-tg-system", "sp-tg-app", "sp-tg-lang",
          "sp-tg-syslang")

TG_FUNCTIONS = ("loadTelegramChats", "telegramPersonas", "paintTelegramForm",
                "addTelegramChat", "telegramPollText", "tgChatRow",
                "telegramChatActions", "openTelegramJoin", "telegramWindowAction",
                "telegramDevice")

EXTRA = r"""
const SRC = { form: { can_manage: true, can_bind: true }, personas: [], flash: null };
let srcRun = { allowed: true, ready: true };
const confirms = [];
globalThis.window = { confirm(t) { confirms.push(t); return true; } };
async function section(path, list, empty, pick, build) {
  calls.push({ section: path });
  const body = globalThis.apiAnswer ? globalThis.apiAnswer(path) : { chats: [] };
  const rows = pick(body) || [];
  globalThis.drawn = rows.map(build);
  return body;
}
"""


def _run_tg(names, body: str, tmp_path, consts=()) -> dict:
    """_run with the Telegram globals at the top level, where the functions
    under test can see them."""
    import json
    import subprocess

    sources = [_const(c) for c in consts] + [_fn(n) for n in names]
    script = tmp_path / "run.js"
    script.write_text(FOUNDATION_STUBS + EXTRA + "\n".join(sources) + "\n(async () => {\n"
                      + body + "\n})().catch((e) => { console.error(e); process.exit(1); });\n",
                      encoding="utf-8")
    out = subprocess.run([NODE, str(script)], capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def _markup() -> str:
    html = _html()
    start = html.index("<!-- F5.3 (2026-09-24): Telegram chats.")
    return html[start:html.index('id="src-tg-empty"', start) + 200]


def _device_markup() -> str:
    html = _html()
    start = html.index("<!-- F5.2 (2026-09-24): what Telegram is told")
    return html[start:html.index("</fieldset>", start) + 11]


def test_the_telegram_section_and_forms_exist_once_and_in_order():
    html = _html()
    for ident in TG_IDS:
        assert html.count(f'id="{ident}"') == 1, ident
    order = [html.index(f'id="{i}"') for i in ("src-all", "src-tg", "src-personas")]
    assert order == sorted(order)


@pytest.mark.parametrize("markup", [_markup, _device_markup], ids=["chats", "device"])
def test_the_telegram_markup_carries_no_inline_style_or_handler(markup):
    block = markup()
    assert not re.search(r"\sstyle\s*=", block, re.I)
    assert not re.search(r"\son[a-z]+\s*=", block, re.I)
    assert "<script" not in block.lower()


def test_the_markup_says_what_the_section_is_for():
    text = re.sub(r"\s+", " ", _markup())
    assert "Each chat is read by one persona, through that persona's egress profile" in text
    assert "no watch term leaves this server" in text
    assert "No Telegram chats are configured." in text
    assert "Read without joining (public chats only)" in text
    device = re.sub(r"\s+", " ", _device_markup())
    assert "Choose something ordinary and keep it for the life of the persona." in device


def test_the_forms_are_wired_at_boot_and_the_chats_load_after_the_personas():
    js = _js()
    assert "$('src-tg-form').addEventListener('submit', addTelegramChat);" in js
    load = _fn("loadSources")
    assert load.index("paintPersonaForm(") < load.index("loadTelegramChats();")


def test_the_new_copy_has_no_lazy_plural_no_dash_and_no_actor():
    for name in TG_FUNCTIONS:
        body = _fn(name)
        strings = re.findall(r"'((?:[^'\\]|\\.)*)'", body)
        for s in strings:
            assert "(s)" not in s and "—" not in s and "–" not in s, (name, s)
            assert " -- " not in s, (name, s)
            assert not re.search(r"\bactor\b", s, re.I), (name, s)
    markup = _markup() + _device_markup()
    assert "—" not in markup and "–" not in markup and "(s)" not in markup


def test_counted_strings_agree():
    assert "countOf(c.deleted_upstream || 0, 'message', 'messages')" in _fn("tgChatRow")


def test_run_rows_paint_rate_limited_warn_and_blocked_bad():
    js = _const("RUN_STATUS_CLASS")
    assert "RATE_LIMITED: 'warn'" in js and "BLOCKED: 'bad'" in js


def test_the_join_form_uses_withstepup_and_the_acts_bind_behind_it():
    join = _fn("openTelegramJoin")
    assert "withStepUp(" in join and "acknowledge_overt: true" in join
    actions = _fn("telegramChatActions")
    for route in ("/member'", "/persona'"):
        chunk = actions[actions.index(route) - 400:actions.index(route)]
        assert "withStepUp(" in chunk, route
    assert "withStepUp(" in _fn("addTelegramChat")
    stop = actions[actions.index("'/deactivate'") - 300:actions.index("'/deactivate'")]
    assert "withStepUp(" not in stop, "stopping is always allowed"


@needs_node
def test_the_telegram_poll_confirm_names_persona_and_egress(tmp_path):
    got = _run(["telegramPollText", "personaLabel"], r"""
    const s = { name: 'Ops chat', persona: { id: 'p1', handle: 'ghost' } };
    const one = telegramPollText(s, { chat: 'c:1300000001', egress: 'exit-two' });
    const hidden = telegramPollText({ name: 'x', persona: { hidden: true,
      label: 'a persona you cannot see' } }, { chat: 'c:5', egress: null });
    console.log(JSON.stringify({ one, hidden }));
    """, tmp_path)
    assert "reads c:1300000001 through Telegram as persona ghost" in got["one"]
    assert "over egress profile exit-two" in got["one"]
    assert "no watch term leaves this server" in got["one"]
    assert "a persona you cannot see" in got["hidden"]


@needs_node
def test_a_due_telegram_chat_shows_its_chat_and_exit_not_a_host(tmp_path):
    got = _run_tg(["dueRow", "dueAgo", "personaLabel", "telegramPollText"], r"""
    globalThis.apiAnswer = () => ({ items_new: 1, items_seen: 1, warnings: [] });
    const row = dueRow({ id: 's1', name: 'Ops chat', kind: 'TELEGRAM', base_url: null,
      max_rps: 0.2, parser_key: 'telegram', requires_authority: true,
      persona: { id: 'p1', handle: 'ghost' },
      telegram: { chat: 'c:1300000001', access_mode: 'MEMBER', egress: 'exit-two' } });
    const button = all(row, (x) => x.tag === 'button')[0];
    await button.listeners.click();
    console.log(JSON.stringify({ text: text(row), confirms }));
    """, tmp_path)
    assert "chat: c:1300000001" in got["text"] and "egress: exit-two" in got["text"]
    assert "persona: ghost" in got["text"] and "host:" not in got["text"]
    assert got["confirms"][0].startswith("Poll Ops chat now?")
    assert "as persona ghost, over egress profile exit-two" in got["confirms"][0]
    assert "s.requires_authority ? authorityPollText(s, host)" in _fn("dueRow")


@needs_node
def test_a_chat_row_draws_its_state_and_offers_the_verbs_it_may_use(tmp_path):
    names = list(TG_FUNCTIONS) + ["personaLabel"]
    got = _run_tg(names, r"""
    SRC.personas = [
      { id: 'p1', handle: 'ghost', platform: 'TELEGRAM', status: 'HEALTHY',
        telegram: { session_enrolled_at: '2026-09-24T10:00:00Z' } },
      { id: 'p2', handle: 'spare', platform: 'TELEGRAM', status: 'HEALTHY',
        telegram: { session_enrolled_at: '2026-09-24T10:00:00Z' } }];
    const unjoined = tgChatRow({ source_id: 's1', name: 'Ops chat', classification: 'AMBER',
      is_active: true, durable_id: 'c:1300000001', peer_type: 'MEGAGROUP',
      access_mode: 'MEMBER', member_since_observed: null, username_at_resolve: 'opschat',
      title_at_resolve: 'Ops', persona: { id: 'p1', handle: 'ghost' },
      egress_profile_name: 'exit-one', authority: { live: false,
      sentence: 'No confirmed authority covers this persona reading this source.' },
      last_message_id: null, deleted_upstream: 2, blocked_reason: null });
    const publicRow = tgChatRow({ source_id: 's2', name: 'News', classification: 'GREEN',
      is_active: false, durable_id: 'c:1300000002', peer_type: 'CHANNEL',
      access_mode: 'PUBLIC_READ', member_since_observed: null, persona: { id: 'p1',
      handle: 'ghost' }, authority: { live: true, sentence: 'in force' },
      last_message_id: 4410, deleted_upstream: 1, blocked_reason: 'Telegram said no' });
    SRC.form = { can_manage: false, can_bind: false };
    const reader = tgChatRow({ source_id: 's3', name: 'Read only', classification: 'GREEN',
      is_active: true, durable_id: 'c:3', peer_type: 'CHANNEL', access_mode: 'PUBLIC_READ',
      persona: { hidden: true, label: 'a persona you cannot see' },
      authority: { live: true, sentence: 's' }, deleted_upstream: 0 });
    console.log(JSON.stringify({
      unjoined: { text: text(unjoined), buttons: buttons(unjoined), chips: chips(unjoined) },
      pub: { text: text(publicRow), buttons: buttons(publicRow), chips: chips(publicRow) },
      reader: { text: text(reader), buttons: buttons(reader) } }));
    """, tmp_path, consts=["TG"])
    u = got["unjoined"]
    assert "chip:member, not joined yet" in u["chips"]
    assert "chip bad:no live authority" in u["chips"]
    assert "No confirmed authority covers" in u["text"], "the sentence is the chip's title"
    assert "deleted upstream: 2 messages" in u["text"]
    assert u["buttons"] == ["Join", "Check membership", "Change persona", "Stop reading"]
    p = u = got["pub"]
    assert "chip:public, not joined" in p["chips"] and "chip:stopped" in p["chips"]
    assert "chip bad:blocked" in p["chips"] and "deleted upstream: 1 message" in p["text"]
    assert p["buttons"] == ["Resume reading"], "a stopped chat is only resumed"
    r = got["reader"]
    assert r["buttons"] == [] and "a persona you cannot see" in r["text"]


@needs_node
def test_the_join_form_needs_the_box_ticked_and_a_note(tmp_path):
    got = _run(["openTelegramJoin"], r"""
    const card = mk('div');
    const reloads = [];
    openTelegramJoin(card, { source_id: 's1' }, (t) => reloads.push(t));
    const wrap = card.children[0];
    const form = wrap.children[1];
    const tick = all(form, (x) => x.tag === 'input' && x.type === 'checkbox')[0];
    const note = all(form, (x) => x.tag === 'input' && x.type === 'text')[0];
    const msg = wrap.children[2];
    await form.listeners.submit({ preventDefault() {} });
    const first = msg.textContent;
    tick.checked = true;
    note.value = 'short';
    await form.listeners.submit({ preventDefault() {} });
    const second = msg.textContent;
    note.value = 'joining for the operation';
    globalThis.apiAnswer = () => ({ notice: 'joined notice' });
    await form.listeners.submit({ preventDefault() {} });
    console.log(JSON.stringify({ first, second, calls, reloads }));
    """, tmp_path)
    assert "Tick the box" in got["first"] and "10 characters" in got["second"]
    sent = [c for c in got["calls"] if c.get("path")]
    assert sent == [{"path": "/collection/telegram/chats/s1/join",
                     "opts": {"method": "POST", "json": {
                         "acknowledge_overt": True,
                         "note": "joining for the operation"}}}]
    assert any("stepup" in c for c in got["calls"]) and got["reloads"] == ["joined notice"]


@needs_node
def test_the_add_form_is_replaced_by_the_servers_sentence_when_telegram_is_off(tmp_path):
    got = _run_tg(["paintTelegramForm", "telegramPersonas", "labelsUpTo", "defaultLabel"],
                  r"""
    SRC.personas = [{ id: 'p1', handle: 'ghost', platform: 'TELEGRAM', status: 'HEALTHY',
      telegram: { session_enrolled_at: 'x' } }];
    TG.body = { telegram: { sentence: 'Telegram collection is off.', ceiling: null } };
    paintTelegramForm();
    const off = { hidden: $('src-tg-box').hidden, sentence: $('src-tg-off').textContent };
    TG.body = { telegram: { sentence: null, ceiling: 'GREEN' } };
    paintTelegramForm();
    const on = { hidden: $('src-tg-box').hidden,
      labels: $('stg-class').children.map((o) => o.value),
      personas: $('stg-persona').children.map((o) => o.value) };
    console.log(JSON.stringify({ off, on }));
    """, tmp_path, consts=["TG"])
    assert got["off"] == {"hidden": True, "sentence": "Telegram collection is off."}
    assert got["on"]["hidden"] is False and got["on"]["labels"] == ["CLEAR", "GREEN"]
    assert got["on"]["personas"] == ["p1"]


@needs_node
def test_a_telegram_persona_row_says_its_session_chats_and_hold_once(tmp_path):
    got = _run_tg(["personaRow", "authorityChip", "personaLabel", "telegramWindowAction"],
                  r"""
    const row = personaRow({ id: 'p1', handle: 'ghost', status: 'HEALTHY',
      platform: 'TELEGRAM', platform_uid: 'u:700000001', machine_lock_code:
      'CREDENTIAL_DUPLICATED', authority: { state: 'LIVE', valid_until: 'x' },
      telegram: { session_enrolled_at: '2026-09-24T10:15:00Z', chats_bound: 3,
        active_window_utc: '07:00-23:00', hold: { kind: 'CREDENTIAL_DUPLICATED',
        until: null, words: 'Telegram refused this persona’s session: it was '
        + 'used from two places at once. Log it out and enrol it again.' } } });
    const fresh = personaRow({ id: 'p2', handle: 'new', status: 'HEALTHY',
      platform: 'TELEGRAM', telegram: { session_enrolled_at: null, chats_bound: 0,
      hold: null } });
    console.log(JSON.stringify({ row: text(row), fresh: text(fresh),
      buttons: buttons(row) }));
    """, tmp_path)
    assert "session: enrolled T(2026-09-24T10:15:00Z)" in got["row"]
    assert "chats: 3" in got["row"]
    assert got["row"].count("Log it out and enrol it again") == 1
    assert "Locked by its platform" not in got["row"], "said once, in Telegram's words"
    assert "No session yet. An operator enrols one on the server." in got["fresh"]
    assert "Set active hours" in got["buttons"]


@needs_node
def test_a_telegram_document_row_names_its_author_forward_and_media(tmp_path):
    got = _run(["collectedDocRow"], r"""
    const row = collectedDocRow({ id: 'd1', title: null, triage_state: 'NEW',
      classification: 'AMBER', source_name: 'Ops chat', author_handle: '@alice',
      posted_at: 'x', version: 1, telegram: { sender_uid: 'u:1300000001',
      sender_handle: '@alice', fwd_from_uid: 'c:1300000002', fwd_from_name: null,
      edit_date: '2026-09-24T11:00:00Z', media_kind: 'photo', is_service: true } }, false);
    console.log(JSON.stringify({ text: text(row), chips: chips(row) }));
    """, tmp_path)
    assert "Telegram message" in got["text"]
    assert "author: @alice, u:1300000001" in got["text"]
    assert "forwarded from: c:1300000002" in got["text"]
    assert "edited: T(2026-09-24T11:00:00Z)" in got["text"]
    assert "chip small:media not collected" in got["chips"]
    assert "chip small:service message" in got["chips"]
    assert "not downloaded" in got["text"]


@needs_node
def test_a_telegram_target_shows_the_confirmer_its_chat(tmp_path):
    got = _run(["authorityTargetText", "personaLabel"], r"""
    const line = authorityTargetText({ source_name: 'Ops chat', source_kind: 'TELEGRAM',
      source_host: null, binding: { persona: { id: 'p', handle: 'ghost' } },
      chat: { durable_id: 'c:1300000001', username_at_resolve: 'opschat',
              title_at_resolve: 'Ops', access_mode: 'MEMBER' } });
    console.log(JSON.stringify({ line }));
    """, tmp_path)
    assert got["line"] == ("Ops chat (TELEGRAM, chat c:1300000001 @opschat, titled Ops, "
                           "read as a member), as ghost")


@needs_node
def test_the_persona_form_sends_the_device_only_for_telegram(tmp_path):
    got = _run(["telegramDevice"], r"""
    const ids = { 'sp-tg-model': 'Pixel 7', 'sp-tg-system': 'Android 14',
      'sp-tg-app': '10.14.5', 'sp-tg-lang': 'en', 'sp-tg-syslang': 'en-GB' };
    for (const [id, v] of Object.entries(ids)) $(id).value = v;
    const fp = {};
    const ok = telegramDevice(fp);
    $('sp-tg-lang').value = 'e';
    const refused = telegramDevice({});
    console.log(JSON.stringify({ ok, fp, refused }));
    """, tmp_path, consts=["TG_DEVICE_FIELDS"])
    assert got["ok"] is None
    assert got["fp"] == {"device_model": "Pixel 7", "system_version": "Android 14",
                         "app_version": "10.14.5", "lang_code": "en",
                         "system_lang_code": "en-GB"}
    assert got["refused"] == "A Telegram persona records its language code, 2 to 8 characters."
    create = _fn("createPersona")
    assert "if ($('sp-platform').value === 'TELEGRAM')" in create
    assert "show($('sp-tg-device'), platform === 'TELEGRAM')" in _fn("paintPersonaIdentity")


def test_the_foundation_stubs_are_the_harness_this_file_extends():
    assert "function rowForm(card, spec)" in FOUNDATION_STUBS
