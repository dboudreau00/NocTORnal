"""Administration, Providers as the console ships it (F15.2,
2026-09-24): the exposure has no default, the consequence of each
level is shown, the key is typed into password inputs that are emptied
before the request goes, enabling echoes the exposure the administrator
read, and only a second administrator is offered Approve.

Pure: reads the shipped source, as test_ui_invariants.py does.
"""
from __future__ import annotations

import re

from test_ui_copy_no_dashes import _html, _js, _source


def test_the_exposure_has_no_default_in_the_form_or_the_request():
    html = _html()
    select = html[html.index('<select id="prv-exposure"'):]
    select = select[:select.index("</select>")]
    first = re.search(r'<option value="([^"]*)"', select)
    assert first and first.group(1) == "", "the first option chooses nothing"
    assert "selected" not in select
    create = _source(_js(), "createProvider")
    assert "if (!body.exposure_level)" in create and "it has no default" in create


def test_every_card_shows_the_consequence_and_the_route_it_leaves_by():
    card = _source(_js(), "providerCard")
    assert "p.consequence" in card and "p.route_words" in card
    assert "Not yet verified against the live service." in card


def test_the_key_is_typed_into_password_inputs_emptied_before_the_request():
    form = _source(_js(), "providerKeyForm")
    assert "input.type = 'password';" in form and "input.autocomplete = 'off';" in form
    emptied = form.index("v.value = ''")
    sent = form.index("providerAct(p, '/secret'")
    assert emptied < sent, "the inputs are emptied before the request goes"
    assert "secret_ciphertext" not in _js()


def test_enabling_echoes_the_exposure_the_administrator_read():
    actions = _source(_js(), "providerActions")
    assert "providerAct(p, '/enable',\n      { confirm_exposure: p.exposure_level }" in actions


def test_only_a_second_administrator_is_offered_approve():
    change = _source(_js(), "providerChangeCard")
    yours = change.index("if (c.yours)")
    approve = change.index("act('Approve'")
    other = change.index("} else {", yours)
    assert yours < other < approve
    assert "act('Withdraw'" in change[yours:other]


def test_the_switch_off_notice_is_drawn_from_the_list_answer():
    load = _source(_js(), "loadProviders")
    assert "list.switch !== 'on'" in load and "NOCTORNAL_OUTBOUND_LOOKUPS is off" in load


def test_no_provider_function_writes_markup():
    js = _js()
    for name in ("providerCard", "providerActions", "providerChangeCard",
                 "providerKeyForm", "loadProviders", "createProvider"):
        body = _source(js, name)
        assert "innerHTML" not in body and "insertAdjacentHTML" not in body, name
