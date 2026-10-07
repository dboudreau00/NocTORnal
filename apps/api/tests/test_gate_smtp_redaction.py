"""An SMTP relay that echoes the password in its refusal does not get it into
the delivery ledger (beta 1 gate 6, 2026-10-07).

`send_smtp` redacted its error text after `secret_in_scope` had ended, so the
exact removal of the live password no longer applied, and a short password
echoed by an AUTH reply (in clear or as its base64) went into the
TransportError that `notify.delivery.detail` and the log keep. Pure: the
relay is a stand-in.
"""
from __future__ import annotations

import base64
import smtplib
from email.message import EmailMessage

import pytest

from noctornal_api import transports

PASSWORD = "Pw0rd9x"


class _EchoingRelay:
    def __init__(self, **_kw):
        pass

    def starttls(self, **_kw):
        return (220, b"ready")

    def login(self, user, password):
        echoed = base64.b64encode(password.encode()).decode()
        raise smtplib.SMTPAuthenticationError(
            535, f"5.7.8 {user} {password} {echoed} rejected".encode())

    def quit(self):
        pass


@pytest.mark.parametrize("port", ["587"])
def test_a_relay_echoing_the_password_is_redacted(monkeypatch, port):
    for name, value in {"SMTP_HOST": "relay.example", "SMTP_PORT": port,
                        "SMTP_USERNAME": "noctornal", "SMTP_PASSWORD": PASSWORD}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(transports, "_RoutedSMTP", _EchoingRelay)
    message = EmailMessage()
    message["To"] = "a@b.example"
    message.set_content("x")
    with pytest.raises(transports.TransportError) as caught:
        transports.send_smtp(message, route=None)
    text = str(caught.value)
    assert text.startswith("SMTP send failed")
    assert PASSWORD not in text
    assert base64.b64encode(PASSWORD.encode()).decode() not in text
