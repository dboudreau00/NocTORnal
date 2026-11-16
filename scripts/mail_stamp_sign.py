"""Stamp a message on the mail server, or check one: the signer half of the mail stamp (docs/19 section 2.1).

The API only verifies. This runs where the deployment's own border MTA runs, after the milters that write
Authentication-Results, and adds X-NocTORnal-Stamp (infra/production/mail-stamp/README.md has the
Postfix filter that calls it):

    mail_stamp_sign.py sign --authserv-id mx.corp.example --key-file /etc/noctornal-stamp/key \\
        --key-id mail:v1 < message.eml > stamped.eml
    mail_stamp_sign.py verify --key-file /etc/noctornal-stamp/key --key-id mail:v1 < stamped.eml

`sign` removes every stamp the message arrived with, then stamps the topmost Authentication-Results
header and the topmost Received header, but only when that Authentication-Results header carries
`--authserv-id`, this server's own name. Anything else (no such header, no Received header, a topmost
header another server wrote) is written out UNCHANGED, exit 0, with one line on stderr: the stamp never
stops mail, and unstamped mail is read as the sender's claim. Exit 75 (EX_TEMPFAIL) is for a key it
cannot use or a read or write that failed, so the MTA defers the message rather than deliver it
unstamped by accident. Exit 2 is a usage error.

`verify` prints one JSON line, `{"valid": ..., "key_id": ..., "reason": ...}`, and exits 0 when the
stamp verifies, 1 when it does not, 2 on a usage or key error: for testing the whole path offline with
.eml files exported from a mailbox. Given no --key-file it reads the API's ring from the environment
(NOCTORNAL_MAIL_STAMP_KEY, _KEY_ID, _KEY_RETIRED).

The key is the base64 text the API's NOCTORNAL_MAIL_STAMP_KEY holds, read from --key-file or, failing
that, from the environment variable of that name; never from the command line, which `ps` shows. A key
file anybody but its owner and group can read, or its group can write, is refused. Nothing this prints
carries the key.

Two files go to the mail server: this one and apps/api/src/noctornal_api/mail_stamp.py, which it loads
from its own directory first and from the repository second. Python 3.8 or later, standard library only.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import stat
import sys
import time
from pathlib import Path

EX_OK = 0
EX_INVALID = 1
EX_USAGE = 2
EX_TEMPFAIL = 75

_HERE = Path(__file__).resolve().parent
_CANDIDATES = (_HERE / "mail_stamp.py",
               _HERE.parent / "apps" / "api" / "src" / "noctornal_api" / "mail_stamp.py")


class _Usage(Exception):
    pass


def _load_module():
    """mail_stamp, by its path: never by putting the package directory on sys.path, where its `http`
    package would stand in for the standard library's."""
    path = next((p for p in _CANDIDATES if p.is_file()), None)
    if path is None:
        raise _Usage("mail_stamp.py is not beside this script, so the signer cannot "
                     "run; copy it from apps/api/src/noctornal_api/")
    spec = importlib.util.spec_from_file_location("mail_stamp", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["mail_stamp"] = module
    spec.loader.exec_module(module)
    return module


def _read_key_file(path: str) -> str:
    try:
        info = os.stat(path)
        if os.name == "posix" and info.st_mode & (stat.S_IRWXO | stat.S_IWGRP):
            raise _KeyFault(f"the key file {path} can be read or written by others, or "
                            f"written by its group; make it root:noctornal-stamp, mode "
                            f"0640, and run this again")
        with open(path, "r", encoding="ascii") as handle:
            return handle.read()
    except _KeyFault:
        raise
    except (OSError, UnicodeError) as exc:
        reason = getattr(exc, "strerror", None) or type(exc).__name__
        raise _KeyFault(f"the key file {path} could not be read ({reason})") from None


class _KeyFault(Exception):
    pass


def _keys(stamp, args, *, for_signing: bool) -> dict:
    """{key id: key} from --key-file or the environment, through the module's own ring reader, which
    names variables and ids and never a key."""
    key_id = args.key_id or os.environ.get(stamp.KEY_ID_ENV, "").strip() or stamp.DEFAULT_KEY_ID
    if args.key_file:
        env = {stamp.KEY_ENV: _read_key_file(args.key_file), stamp.KEY_ID_ENV: key_id}
    elif for_signing:
        env = {stamp.KEY_ENV: os.environ.get(stamp.KEY_ENV, ""), stamp.KEY_ID_ENV: key_id}
    else:
        env = dict(os.environ)
        if args.key_id:
            env[stamp.KEY_ID_ENV] = args.key_id
    try:
        keys = stamp.ring(env)
    except stamp.StampKeyError as exc:
        raise _KeyFault(str(exc)) from None
    if not keys:
        raise _KeyFault(f"no key: give --key-file, or set {stamp.KEY_ENV}")
    return keys


def _note(text: str) -> None:
    sys.stderr.write(f"mail_stamp_sign: {text}\n")


def _sign(stamp, args) -> int:
    try:
        keys = _keys(stamp, args, for_signing=True)
    except _KeyFault as exc:
        _note(f"not stamped, deferred: {exc}")
        return EX_TEMPFAIL
    key_id, key = next(iter(keys.items()))
    try:
        data = sys.stdin.buffer.read()
    except OSError as exc:
        _note(f"the message could not be read ({exc.strerror or type(exc).__name__}); deferred")
        return EX_TEMPFAIL
    try:
        out = stamp.sign(data, key, key_id, now=int(time.time()), authserv_id=args.authserv_id)
    except (stamp.StampKeyError, ValueError) as exc:
        _note(f"not stamped, deferred: {exc}")
        return EX_TEMPFAIL
    if out is None:
        _note(f"left unstamped: {stamp.refusal(data, authserv_id=args.authserv_id)}")
        out = stamp.strip_stamps(data)
    try:
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.flush()
    except OSError as exc:
        _note(f"the message could not be written ({exc.strerror or type(exc).__name__}); deferred")
        return EX_TEMPFAIL
    return EX_OK


def _verify(stamp, args) -> int:
    try:
        keys = _keys(stamp, args, for_signing=False)
    except _KeyFault as exc:
        _note(str(exc))
        return EX_USAGE
    result = stamp.verify(sys.stdin.buffer.read(), keys)
    print(json.dumps({"valid": result.ok, "key_id": result.key_id,
                      "reason": result.reason or None}))
    return EX_OK if result.ok else EX_INVALID


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name, what in (("sign", "stamp the message on stdin and write it to stdout"),
                       ("verify", "check the stamp of the message on stdin")):
        cmd = sub.add_parser(name, help=what)
        cmd.add_argument("--key-file", help="a file holding the base64 key (root:noctornal-stamp, 0640)")
        cmd.add_argument("--key-id", help="the key's id, mail:v1 by default")
        if name == "sign":
            cmd.add_argument("--authserv-id", required=True,
                             help="this server's authserv-id, as its milters write it in "
                                  "Authentication-Results")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return EX_USAGE if exc.code else EX_OK
    try:
        stamp = _load_module()
    except _Usage as exc:
        _note(str(exc))
        return EX_TEMPFAIL if args.command == "sign" else EX_USAGE
    return _sign(stamp, args) if args.command == "sign" else _verify(stamp, args)


if __name__ == "__main__":
    sys.exit(main())
