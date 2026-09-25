"""What an event puts on Jira (notify F7, 2026-09-24).

Pure: no database and no network. The renderer reads the subject and the
summary only (`Outgoing` carries no body), and at STUB exposure nothing,
not even the grouping of work by case, carries case identity.
"""
from __future__ import annotations

import dataclasses
import json
import re
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from noctornal_api import jira
from noctornal_api.transports import Outgoing

BASE = "https://noctornal.example.org"
OFF_STYLE = "[" + chr(0x2013) + chr(0x2014) + r"]| -- |\(s\)"


def _out(**kw):
    values = dict(delivery_id=uuid4(), notification_id=uuid4(), channel="JIRA", attempts=0,
                  recipient_id=uuid4(), case_id=uuid4(), kind="APPROVAL_REQUESTED",
                  priority=2, subject="OP-KESTREL-26: a second signature is needed",
                  summary="Someone on OP-KESTREL-26 is asking for a second signature.",
                  classification="AMBER", compartments=frozenset(), address=None,
                  case_code="OP-KESTREL-26", object_type="approval_request",
                  object_id=uuid4(), raised_at=datetime(2026, 9, 24, 12, 5, tzinfo=timezone.utc),
                  event_id=uuid4())
    values.update(kw)
    return Outgoing(**values)


def _text(rendered) -> str:
    return json.dumps(dataclasses.asdict(rendered), ensure_ascii=False)


def test_the_jira_renderer_cannot_reach_the_notification_body():
    assert "body" not in {f.name for f in dataclasses.fields(Outgoing)}
    out = _out()
    r = jira.render(out, exposure="SUMMARY", api_version=2, ref="abcdefghijklmnop",
                    mark="0123456789ab", base=BASE)
    assert "detail only in the app" not in _text(r)


def test_a_stub_issue_carries_no_case_code_kind_priority_or_tlp():
    out = _out()
    for v in (2, 3):
        r = jira.render(out, exposure="STUB", api_version=v, ref="abcdefghijklmnop",
                        mark="0123456789ab", base=BASE)
        text = _text(r)
        for leak in ("OP-KESTREL", "APPROVAL", "priority", "TLP", "tlp-", "AMBER"):
            assert leak not in text, (v, leak)
        assert set(r.labels) == {"noctornal", "noctornal-ref-abcdefghijklmnop"}


def test_stub_work_is_keyed_per_event_so_no_case_groups_issues():
    case, obj = uuid4(), uuid4()
    one = _out(case_id=case, object_id=obj)
    two = _out(case_id=case, object_id=obj)
    assert jira.work_key(one, "STUB") != jira.work_key(two, "STUB")
    assert jira.work_key(one, "STUB") == jira.work_key(one, "STUB")
    assert jira.work_key(one, "SUBJECT") == jira.work_key(two, "SUBJECT")


def test_subject_exposure_sends_subject_task_tlp_and_link_only():
    out = _out()
    r = jira.render(out, exposure="SUBJECT", api_version=2, ref="abcdefghijklmnop",
                    mark="0123456789ab", base=BASE)
    assert r.summary == "[NocTORnal] OP\\-KESTREL\\-26: a second signature is needed" \
        or r.summary == "[NocTORnal] OP-KESTREL-26: a second signature is needed"
    assert "Someone on" not in r.description
    assert jira.JIRA_TASKS["APPROVAL_REQUESTED"] in r.description
    assert "TLP:AMBER" in r.description and BASE + "/ui/" in r.description
    assert r.description.endswith("NocTORnal ref 0123456789ab")
    assert "tlp-amber" in r.labels and "noctornal-p2" in r.labels


def test_summary_exposure_adds_exactly_the_summary_line():
    out = _out()
    subject = jira.render(out, exposure="SUBJECT", api_version=2, ref="abcdefghijklmnop",
                          mark="0123456789ab", base=BASE)
    summary = jira.render(out, exposure="SUMMARY", api_version=2, ref="abcdefghijklmnop",
                          mark="0123456789ab", base=BASE)
    extra = set(summary.description.split("\n")) - set(subject.description.split("\n"))
    assert len(extra) == 1 and "Someone on" in extra.pop()


def test_routing_is_an_allowlist():
    from noctornal_api.notifications import KINDS
    assert set(jira.JIRA_TASKS) <= set(KINDS)
    assert not set(jira.JIRA_TASKS) & jira.JIRA_NEVER_KINDS
    assert not jira.routable("NOT_A_KIND")
    for kind in KINDS:
        assert jira.routable(kind) == (kind in jira.JIRA_TASKS)


def test_break_glass_and_escalation_and_this_groups_kinds_are_never_routable():
    for kind in ("BREAK_GLASS_INVOKED", "ESCALATION", "PROVIDER_CHANGE_REQUESTED",
                 "LOOKUP_SIGNOFF_REQUESTED", "LOOKUP_SIGNOFF_DECIDED"):
        assert kind in jira.JIRA_NEVER_KINDS and not jira.routable(kind)


def test_wiki_markup_in_a_case_code_is_escaped_on_data_center():
    out = _out(subject="OP-*BOLD*-{code}: [link|http://x] !img!")
    r = jira.render(out, exposure="SUBJECT", api_version=2, ref="abcdefghijklmnop",
                    mark="0123456789ab", base=BASE)
    line = r.comment.split("\n")[0]
    for raw in ("*BOLD*", "{code}", "[link|", "!img!"):
        assert raw not in line
    assert "\\*BOLD\\*" in line


def test_cloud_descriptions_are_adf_text_nodes_only():
    r = jira.render(_out(), exposure="SUMMARY", api_version=3, ref="abcdefghijklmnop",
                    mark="0123456789ab", base=BASE)
    doc = r.description
    assert doc["type"] == "doc" and doc["version"] == 1
    for para in doc["content"]:
        assert para["type"] == "paragraph"
        for node in para["content"]:
            assert node["type"] == "text"
            for mark in node.get("marks", []):
                assert mark == {"type": "link", "attrs": {"href": BASE + "/ui/"}}


def test_labels_have_no_spaces_and_fit():
    out = _out(kind="MERGE_PERFORMED", classification="AMBER")
    r = jira.render(out, exposure="SUBJECT", api_version=2, ref="abcdefghijklmnop",
                    mark="0123456789ab", base=BASE)
    for label in r.labels:
        assert " " not in label and len(label) <= 255


def test_summary_is_capped_at_255_and_stripped_of_control_characters():
    out = _out(subject="A\x00B\x1b" + "x" * 400)
    r = jira.render(out, exposure="SUBJECT", api_version=3, ref="abcdefghijklmnop",
                    mark="0123456789ab", base=BASE)
    assert len(r.summary) == 255 and "\x00" not in r.summary and "\x1b" not in r.summary


def test_the_marker_is_per_event_and_issue_and_names_no_internal_id():
    e1, e2 = uuid4(), uuid4()
    assert jira.marker("aaaaaaaaaaaaaaaa", e1) != jira.marker("aaaaaaaaaaaaaaaa", e2)
    assert jira.marker("aaaaaaaaaaaaaaaa", e1) != jira.marker("bbbbbbbbbbbbbbbb", e1)
    mark = jira.marker("aaaaaaaaaaaaaaaa", e1)
    assert re.fullmatch(r"[0-9a-f]{12}", mark) and mark not in str(e1)


def test_work_key_groups_request_and_decision_and_merge_and_reversal():
    case, request = uuid4(), uuid4()
    ask = _out(case_id=case, kind="APPROVAL_REQUESTED", object_type="approval_request",
               object_id=request)
    decided = _out(case_id=case, kind="APPROVAL_DECIDED", object_type="approval_request",
                   object_id=request)
    assert jira.work_key(ask, "SUBJECT") == jira.work_key(decided, "SUBJECT")
    merge = uuid4()
    a = _out(case_id=case, kind="MERGE_PERFORMED", object_type="node_merge", object_id=merge)
    b = _out(case_id=case, kind="MERGE_REVERSED", object_type="node_merge", object_id=merge)
    assert jira.work_key(a, "SUMMARY") == jira.work_key(b, "SUMMARY")


def test_no_jira_text_carries_a_dash_or_a_hedged_plural():
    texts = list(jira.JIRA_TASKS.values()) + list(jira.EXPOSURE_WORDS.values()) + [
        jira.EDIT_SCREEN_CAVEAT, jira.EDIT_SCREEN_FAULT]
    for v in (2, 3):
        for exposure in jira.EXPOSURES:
            texts.append(_text(jira.render(_out(), exposure=exposure, api_version=v,
                                           ref="abcdefghijklmnop", mark="0123456789ab",
                                           base=BASE)))
    for text in texts:
        assert not re.search(OFF_STYLE, text), text


@pytest.mark.parametrize("n,words", [(1, "1 relationship."), (3, "3 relationships.")])
def test_merge_summaries_agree_in_number(n, words):
    import inspect

    from noctornal_api import notify_events
    src = inspect.getsource(notify_events.merge_performed)
    assert "relationship(" not in src
    from noctornal_api.wording import count_of
    assert count_of(n, "relationship", "relationships") + "." == words
