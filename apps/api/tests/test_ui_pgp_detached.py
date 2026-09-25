"""Detached signatures in the console (F10a, comms, 2026-09-24).

Pure: reads the shipped static assets, and runs `bytesToBase64` under node
when node is installed, so the padding defect (a btoa per slice puts '='
in the middle of the stream) is caught by behaviour, not only by shape.
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8")


def _fn(name: str) -> str:
    js = _js()
    m = re.search(rf"^(?:async )?function {re.escape(name)}\(", js, flags=re.M)
    assert m, f"app.js has no top-level function {name}"
    return js[m.start():js.index("\n}", m.start()) + 2]


def test_btoa_is_called_once_outside_the_loop():
    body = _fn("bytesToBase64")
    assert body.count("btoa(") == 1
    loop = body[body.index("for ("):body.index("}", body.index("for ("))]
    assert "btoa(" not in loop
    assert "0x8000" in body and "String.fromCharCode.apply" in body


def _node() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    windows = r"C:\Program Files\nodejs\node.exe"
    return windows if os.path.isfile(windows) else None


@pytest.mark.skipif(_node() is None, reason="node is not installed")
def test_bytes_to_base64_matches_python_across_slice_boundaries():
    script = _fn("bytesToBase64") + """
const out = [];
for (const n of [0, 1, 2, 3, 0x8000 - 1, 0x8000, 0x8000 + 1, 0x8000 * 2 + 2]) {
  const bytes = new Uint8Array(n);
  for (let i = 0; i < n; i++) bytes[i] = (i * 7 + 3) & 255;
  out.push(bytesToBase64(bytes.buffer));
}
console.log(JSON.stringify(out));
"""
    got = json.loads(subprocess.run([_node(), "-e", script], capture_output=True,
                                    text=True, check=True).stdout)
    want = [base64.b64encode(bytes((i * 7 + 3) & 255 for i in range(n))).decode()
            for n in (0, 1, 2, 3, 0x8000 - 1, 0x8000, 0x8000 + 1, 0x8000 * 2 + 2)]
    assert got == want


def test_the_browser_refuses_oversized_files_before_sending():
    js = _js()
    assert "const PGP_DATA_MAX = 1000000;" in js
    assert "const PGP_SIG_MAX = 65536;" in js
    read = _fn("readPgpFile")
    assert "file.size > limit" in read
    verify = _fn("verifyPgp")
    assert "readPgpFile($('comms-pgp-sig-file'), PGP_SIG_MAX" in verify
    assert "readPgpFile($('comms-pgp-data-file'), PGP_DATA_MAX" in verify


def test_a_detached_check_sends_one_signature_and_one_data_field():
    verify = _fn("verifyPgp")
    assert "json.signature_base64 = bytesToBase64(sig)" in verify
    assert "json.signed_data_base64 = bytesToBase64(data)" in verify
    assert "json.signature = " in verify and "json.signed_data = " in verify


def test_the_outcome_shows_the_form_and_the_subkey():
    body = _fn("pgpOutcome")
    assert "body.form === 'DETACHED'" in body
    assert "signing_primary_fingerprint" in body and "'signed by subkey'" in body


def test_the_detached_inputs_are_cleared_on_a_switch():
    js = _js()
    resets = "".join(js[m.start():js.index("\n});", m.start())]
                     for m in re.finditer(r"\nonCaseSwitch\(\(\) => \{", js))
    for element in ("comms-pgp-sig", "comms-pgp-sig-file", "comms-pgp-data",
                    "comms-pgp-data-file"):
        assert f"'{element}'" in resets, element
    assert "$('comms-pgp-kind-clear').checked = true" in resets


def test_the_markup_has_both_forms_and_no_inline_style():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    for element in ("comms-pgp-kind-clear", "comms-pgp-kind-detached",
                    "comms-pgp-clear-box", "comms-pgp-detached-box",
                    "comms-pgp-sig", "comms-pgp-sig-file", "comms-pgp-data",
                    "comms-pgp-data-file"):
        assert f'id="{element}"' in html, element
    assert "Upload the signed file itself when you have it." in html
    start = html.index('id="comms-pgpkey"')
    end = html.index('id="comms-pgp-ledger-empty"')
    assert "style=" not in html[start:end]


def test_the_radio_rule_is_scoped_to_the_pgp_choices():
    """The PGP choices style their radios and no others. A bare
    input[type="radio"] rule restyled every radio in the console (the case
    status dialog, the ACH stance and decision), outside the Comms pane
    (F10a, 2026-09-24). Every PGP radio sits in a .pgp-choice
    fieldset, so the scoped rule reaches all of them and nothing else."""
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    bare = [line for line in css.splitlines()
            if re.match(r'\s*input\[type="radio"\]', line)
            or re.search(r'[,}]\s*input\[type="radio"\]', line)]
    assert bare == []
    assert ('.pgp-choice input[type="radio"] { width: auto; '
            'accent-color: var(--accent-dim); }') in css
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    # The PGP radios (name="comms-pgp..."); other panes' radios, such as
    # the collection authority form's scope (2026-09-25), are styled
    # by their own scoped rules, and the bare-rule check above covers them.
    radios = [m.start() for m in re.finditer(r'<input\b[^>]*>', html)
              if 'type="radio"' in m.group(0) and 'name="comms-pgp' in m.group(0)]
    assert radios
    for at in radios:
        opened = html.rfind('<fieldset class="pgp-choice">', 0, at)
        assert opened >= 0 and html.rfind("</fieldset>", 0, at) < opened, at
