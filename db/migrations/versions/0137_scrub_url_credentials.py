"""Take the passwords and tokens out of the URLs already stored
(graph-url-selector-keeps-credentials, review 2026-10-03).

## Why

`url_norm` used to keep a URL's userinfo (`user:password@`) and its query
byte for byte, and a capture of a stealer line or a leak paste proposed the
link with that normal form as its label. Accepting it wrote the victim's
password onto the graph as an entity label, into the selector index, and
into every search, report and export that prints either. The code stops
doing that from this revision on (the normaliser drops the userinfo and
every credential-bearing query value, a capture redacts what it copies, and
accepting an old proposal that still carries one is refused). This revision
deals with what is already stored.

## What it rewrites

Only rows of the tables below, and only where a URL carries userinfo or a
credential-bearing query value (the rules are the normaliser's, copied
here and frozen: a migration does not import application code).

- `core.selector`, URL and SOCIAL_URL: `raw_value` redacted, `norm_value`
  re-keyed to the canonical form without the credential. When another row of
  the case already holds that form, the credentialled row is not folded into
  it (re-pointing the foreign keys of merges and lookups is a different,
  riskier change); it keeps its owner and counts and its `norm_value`
  becomes `redacted:<its id>`, which no lookup can match.
- `core.node`: the label of an entity that is a URL, and any URL inside a
  label, and `attrs.raw_value`. Each rewritten entity gets a SYSTEM audit
  event naming the fields and no value.
- `collect.proposal`: the label, the `attrs.raw_value` and the rationale of
  a proposal, in every state. A rationale's context window may have cut a
  link before its scheme; the credential-bearing pairs of its query,
  fragment or path, and a `//user:pass@` authority, are found there too
  (upgrade gate, 2026-10-07, on an Alpha 7a estate).
- `collect.extraction`: `raw_value` and `norm_value` of URL rows.
- `core.assertion.prior_value` (0136): the label or `attrs.raw_value` a
  correction replaced, when it carried a credential. 0136 copied them from the
  audit rows, and a retraction restores from them, so a credential kept there
  would be put back on the graph. Only this derived copy is rewritten; no
  other column of a claim is.

One summary SYSTEM audit event carries the counts.

## What it leaves

- **A claim's rationale.** A claim accepted from such a proposal copied its
  context window into its own rationale, and a claim's columns are never
  written again (invariant 5; the owner has not decided to amend it). Those
  rationales keep the credential. docs/17 lists the owner-run statement, and
  the cost.
- The captured document's text, which is the pasted source as received, and
  `audit.event` detail (invariant 6).
- A credential that is not inside a URL: a password in a pasted `user:pass`
  line has no shape to find. Nor does a proposal's context window that cut
  a link inside its userinfo.
- A selector read out of the userinfo of a link that is not http or https
  (`mysql://root:Secret123@db.example/app` was read as the e-mail address
  `Secret123@db.example`). Nothing stored says so: it looks like any
  e-mail address, and only the document it was found in does. The code no
  longer reads one (the extractor skips a link's userinfo), and accepting a
  pending proposal found inside one is refused. Entities already accepted
  from one are found by the query in docs/17.

The rules are the verify round's (2026-10-03): a bounded scheme, `code`
and `;` or percent-encoded credential parameters, a credential-bearing
path parameter (`;jsessionid=`), a link inside a link with a credential of
its own, and a `:login:password` pair written after a path (the stealer-log
layout), which ends the link there.

A row that cannot be rewritten (a trigger refuses it) is counted and
printed, and the upgrade goes on: the rest are scrubbed and the count says
how many remain.

## Downgrade

Nothing. The credentials are not kept anywhere to be put back, and putting
a password back on the graph is not a rollback anyone wants. The summary
audit event stays (`audit.event` is append-only).
"""
import re
from urllib.parse import unquote

from alembic import op
from psycopg.types.json import Json

revision = "0137"
down_revision = "0136"
branch_labels = None
depends_on = None

#: The `by` every event of this revision carries.
BY = "the upgrade that took credentials out of stored URLs"

#: The selector types normalised as URLs, as of this revision.
URL_TYPES = ("URL", "SOCIAL_URL")

#: Frozen from `noctornal_ontology.normalisers` as of 2026-10-03 (the verify
#: round's rules: `code`, a bounded scheme, `;` and percent-encoded
#: parameters, path parameters, nested links and the `:login:password` tail).
_SECRET_QUERY_KEYS = frozenset({
    "key", "apikey", "pass", "passwd", "password", "pwd", "pw", "secret",
    "token", "auth", "authorization", "sig", "signature", "jwt", "otp",
    "sid", "sessid", "phpsessid", "session", "sessionid", "sessionkey",
    "credential", "credentials", "authkey", "passphrase", "passcode",
    "bearer",
    "code", "authcode", "oauthcode",
})
_SECRET_QUERY_SUFFIXES = ("token", "secret", "password", "passwd", "apikey",
                          "accesskey", "secretkey", "privatekey", "signature",
                          "sessionid", "credential")
_NOT_ALNUM = re.compile(r"[^a-z0-9]")
_URL_IN_TEXT = re.compile(r"\b[a-z][a-z0-9+.-]{0,63}+://[^\s<>\"]+", re.I)
_URL_TAIL = ".,;:!?)]}>'\""
_WHOLE_URL = re.compile(r"[a-z][a-z0-9+.-]*://\S+", re.I)
_REDACTED = "REDACTED"
_MAX_NESTING = 6
_PAIR_SEP = re.compile(r"([&;])")
_PATH_PARAM = re.compile(r";([^;/=]*)=[^;/]*")
_LOGIN_TAIL = re.compile(r"(/[^/?#:@]*):[^/?#]*@")


def _secret_query_key(name):
    key = _NOT_ALNUM.sub("", unquote(name.replace("+", " ")).lower())
    return key in _SECRET_QUERY_KEYS or key.endswith(_SECRET_QUERY_SUFFIXES)


def _split_authority(url):
    scheme, sep, rest = url.partition("://")
    if not sep or not scheme:
        return None
    end = len(rest)
    for ch in "/?#":
        i = rest.find(ch)
        if i != -1:
            end = min(end, i)
    return scheme + sep, rest[:end], rest[end:]


def _userinfo_end(authority, rest):
    if "@" in authority:
        return authority.rindex("@")
    if authority.startswith("[") or authority.count(":") != 1:
        return None
    port = authority.rsplit(":", 1)[1]
    if port == "" or port.isdigit() or "@" not in rest:
        return None
    return len(authority) + rest.index("@")


def _strip_userinfo(v):
    parts = _split_authority(v)
    if parts is None:
        return v
    head, authority, rest = parts
    at = _userinfo_end(authority, rest)
    if at is None:
        return v
    return head + (authority + rest)[at + 1:]


def _first_of(s, chars):
    return min((i for i in (s.find(c) for c in chars) if i != -1),
               default=len(s))


def _piece_name_is_secret(piece):
    if _secret_query_key(piece.partition("=")[0]):
        return True
    plain = unquote(piece)
    return plain != piece and "=" in plain and _secret_query_key(
        plain.partition("=")[0])


def _nested_credential(text):
    if _redact_text(text, 1) != text:
        return True
    plain = unquote(text)
    return plain != text and _redact_text(plain, 1) != plain


def _piece_is_secret(piece):
    name, eq, value = piece.partition("=")
    return _piece_name_is_secret(piece) or _nested_credential(
        value if eq else piece)


def _drop_secret_query(query):
    if not query:
        return query
    parts = _PAIR_SEP.split(query)
    out = []
    for i in range(0, len(parts), 2):
        if not _piece_is_secret(parts[i]):
            out.append((parts[i - 1] if i else "", parts[i]))
    return "".join((sep if n else "") + piece
                   for n, (sep, piece) in enumerate(out))


def _drop_secret_path_params(path):
    if ";" not in path:
        return path
    return _PATH_PARAM.sub(
        lambda m: "" if _secret_query_key(m.group(1)) else m.group(0), path)


def _clean_path_part(s):
    parts = _split_authority(s)
    if parts is None:
        return s
    head, authority, rest = parts
    cut = _first_of(rest, "?#")
    path, after = rest[:cut], rest[cut:]
    path = _URL_IN_TEXT.sub(lambda m: _strip_userinfo(m.group(0)), path)
    tail = _LOGIN_TAIL.search(path)
    if tail is not None:
        return head + authority + path[:tail.end(1)]
    return head + authority + path + after


def _redact_piece(piece, depth):
    name, eq, value = piece.partition("=")
    if eq and value and _secret_query_key(name):
        return name + "=" + _REDACTED
    if not eq:
        plain = unquote(piece)
        if plain != piece and "=" in plain and _secret_query_key(
                plain.partition("=")[0]):
            return _REDACTED
    body = value if eq else piece
    inner = _redact_text(body, depth + 1)
    if inner != body:
        return (name + "=" if eq else "") + inner
    plain = unquote(body)
    if plain != body and _redact_text(plain, depth + 1) != plain:
        return (name + "=" if eq else "") + _REDACTED
    return piece


def _redact_pairs(pairs, depth):
    parts = _PAIR_SEP.split(pairs)
    for i in range(0, len(parts), 2):
        parts[i] = _redact_piece(parts[i], depth)
    return "".join(parts)


def _redact_path(path, depth):
    path = _PATH_PARAM.sub(
        lambda m: (m.group(0).partition("=")[0] + "=" + _REDACTED
                   if _secret_query_key(m.group(1)) else m.group(0)), path)
    path = _redact_text(path, depth + 1)
    tail = _LOGIN_TAIL.search(path)
    if tail is not None:
        path = path[:tail.end(1)] + ":" + _REDACTED
    return path


def _redact_text(text, depth=0):
    """Text with every URL's userinfo and credential-bearing query or
    fragment value replaced by REDACTED, everything else as written. A link
    inside a link is read to _MAX_NESTING levels, and deeper is REDACTED."""
    if depth > _MAX_NESTING:
        return _REDACTED if _URL_IN_TEXT.search(text) else text

    def one(m):
        found = m.group(0)
        url = found.rstrip(_URL_TAIL)
        tail = found[len(url):]
        parts = _split_authority(url)
        if parts is None:
            return found
        head, authority, rest = parts
        at = _userinfo_end(authority, rest)
        if at is not None:
            _, host, rest = _split_authority(head + (authority + rest)[at + 1:])
            authority = _REDACTED + "@" + host
        f = rest.find("#")
        fragment = "" if f == -1 else "#" + _redact_pairs(rest[f + 1:], depth)
        body = rest if f == -1 else rest[:f]
        q = body.find("?")
        path = body if q == -1 else body[:q]
        query = "" if q == -1 else "?" + _redact_pairs(body[q + 1:], depth)
        return (head + authority + _redact_path(path, depth) + query
                + fragment + tail)
    return _URL_IN_TEXT.sub(one, text)


#: A context window the extractor cut before a link's scheme (upgrade gate,
#: 2026-10-07): what is left is no URL to `_redact_text`, but its query,
#: fragment and path-parameter pairs, and a `//user:pass@` authority, still
#: read as such. A window cut inside the userinfo itself has no shape left.
_CUT_PAIR = re.compile(r"(?<=[?&#;])([^=&#;?\s]+)=([^&#;\s]+)")
_CUT_USERINFO = re.compile(r"(?<![a-z0-9+.-]:)//[^/\s@]+@", re.I)


def _redact_cut(text):
    """A proposal's rationale with the credential of a link its context
    window cut redacted as well; a pair with a plain name is left as it is."""
    text = _CUT_PAIR.sub(
        lambda m: (m.group(1) + "=" + _REDACTED
                   if _secret_query_key(m.group(1)) and m.group(2) != _REDACTED
                   else m.group(0)), text)
    return _CUT_USERINFO.sub("//" + _REDACTED + "@", text)


def _scrub_url(v):
    """A stored canonical URL without any credential; everything else byte
    for byte."""
    s = _clean_path_part(_strip_userinfo(v))
    f = s.find("#")
    body, fragment = (s, "") if f == -1 else (s[:f], s[f:])
    q = body.find("?")
    path, query = (body, "") if q == -1 else (body[:q], body[q + 1:])
    kept = _drop_secret_query(query)
    bare = _drop_secret_path_params(path)
    if kept == query and bare == path:
        return s
    return bare + ("?" + kept if kept else "") + fragment


def _scrub_label(label):
    """A label that IS a URL becomes its canonical form without the
    credential; a label with a URL inside it has that URL redacted."""
    if _WHOLE_URL.fullmatch(label.strip()):
        return _scrub_url(label.strip())
    return _redact_text(label)


def _audit(conn, action, object_type, object_id, case_id, detail):
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, case_id,
                detail)
           VALUES (NULL, 'SYSTEM', %s, %s, %s, %s, %s)""",
        (action, object_type, object_id, case_id, Json(dict(detail, by=BY))))


def scrub(conn):
    """Rewrite what carries a credential; returns the counts. Idempotent: a
    second run finds nothing, because a rewritten row carries none."""
    import psycopg
    done = {"selectors": 0, "tombstoned": 0, "nodes": 0, "proposals": 0,
            "extractions": 0, "priors": 0, "failed": 0}

    def attempt(statement, params):
        try:
            with conn.transaction():
                conn.execute(statement, params)
            return True
        except psycopg.Error:
            done["failed"] += 1
            return False

    for (sid, case_id, stype, raw, norm) in conn.execute(
            """SELECT id, case_id, selector_type, raw_value, norm_value
                 FROM core.selector
                WHERE selector_type = ANY(%s)
                  AND (raw_value ~ '[@?#;]' OR norm_value ~ '[@?;]')
                ORDER BY created_at, id""", (list(URL_TYPES),)).fetchall():
        new_raw, new_norm = _redact_text(raw), _scrub_url(norm)
        if new_raw == raw and new_norm == norm:
            continue
        tomb = False
        if new_norm != norm and conn.execute(
                """SELECT 1 FROM core.selector
                    WHERE case_id = %s AND selector_type = %s
                      AND norm_value = %s AND id <> %s""",
                (case_id, stype, new_norm, sid)).fetchone():
            new_norm, tomb = "redacted:" + str(sid), True
        if attempt("UPDATE core.selector SET raw_value = %s, norm_value = %s "
                   "WHERE id = %s", (new_raw, new_norm, sid)):
            done["selectors"] += 1
            done["tombstoned"] += tomb

    for (nid, case_id, label, attrs) in conn.execute(
            """SELECT id, case_id, label, attrs FROM core.node
                WHERE label ~ '://' OR (attrs ->> 'raw_value') ~ '://'
                ORDER BY id""").fetchall():
        attrs = dict(attrs or {})
        fields = []
        new_label = _scrub_label(label) if "://" in label else label
        if new_label != label:
            fields.append("label")
        raw = attrs.get("raw_value")
        if isinstance(raw, str) and _redact_text(raw) != raw:
            attrs["raw_value"] = _redact_text(raw)
            fields.append("attrs.raw_value")
        if not fields:
            continue
        if attempt("UPDATE core.node SET label = %s, attrs = %s, "
                   "updated_at = now() WHERE id = %s",
                   (new_label, Json(attrs), nid)):
            done["nodes"] += 1
            _audit(conn, "NODE_URL_CREDENTIAL_REDACTED", "node", nid, case_id,
                   {"fields": fields})

    for (pid, kind, payload, rationale) in conn.execute(
            """SELECT id, kind, payload, rationale FROM collect.proposal
                WHERE rationale ~ '://' OR payload::text ~ '://'
                ORDER BY id""").fetchall():
        payload = dict(payload or {})
        new_rationale = _redact_cut(_redact_text(rationale)) \
            if isinstance(rationale, str) else rationale
        changed = new_rationale != rationale
        if kind == "NODE":
            label = payload.get("label")
            if isinstance(label, str) and "://" in label:
                new_label = _scrub_label(label)
                if new_label != label:
                    payload["label"] = new_label
                    changed = True
            attrs = dict(payload.get("attrs") or {})
            raw = attrs.get("raw_value")
            if isinstance(raw, str) and _redact_text(raw) != raw:
                attrs["raw_value"] = _redact_text(raw)
                payload["attrs"] = attrs
                changed = True
        if changed and attempt(
                "UPDATE collect.proposal SET payload = %s, rationale = %s "
                "WHERE id = %s", (Json(payload), new_rationale, pid)):
            done["proposals"] += 1

    for (xid, raw, norm) in conn.execute(
            """SELECT id, raw_value, norm_value FROM collect.extraction
                WHERE selector_type = ANY(%s)
                  AND (raw_value ~ '[@?#;]' OR norm_value ~ '[@?;]')
                ORDER BY id""", (list(URL_TYPES),)).fetchall():
        new_raw, new_norm = _redact_text(raw), _scrub_url(norm)
        if (new_raw, new_norm) != (raw, norm) and attempt(
                "UPDATE collect.extraction SET raw_value = %s, norm_value = %s "
                "WHERE id = %s", (new_raw, new_norm, xid)):
            done["extractions"] += 1

    # The value a correction replaced (0136), copied from the audit row when
    # the column was filled: a label that carried a credential must not be
    # kept there to be put back by a retraction. Only this derived copy is
    # rewritten; the claim's own columns are not.
    for (aid, prior) in conn.execute(
            """SELECT id, prior_value FROM core.assertion
                WHERE prior_value IS NOT NULL AND prior_value::text ~ '://'
                ORDER BY id""").fetchall():
        prior = dict(prior)
        changed = False
        label = prior.get("label")
        if isinstance(label, str) and "://" in label:
            new_label = _scrub_label(label)
            if new_label != label:
                prior["label"] = new_label
                changed = True
        attrs = prior.get("attrs")
        if isinstance(attrs, dict):
            raw = attrs.get("raw_value")
            if isinstance(raw, str) and _redact_text(raw) != raw:
                prior["attrs"] = dict(attrs, raw_value=_redact_text(raw))
                changed = True
        if changed and attempt(
                "UPDATE core.assertion SET prior_value = %s WHERE id = %s",
                (Json(prior), aid)):
            done["priors"] += 1

    if any(done[k] for k in ("selectors", "nodes", "proposals", "extractions",
                             "priors", "failed")):
        _audit(conn, "URL_CREDENTIALS_SCRUBBED", "deployment", None, None, done)
    return done


def upgrade() -> None:
    done = scrub(op.get_bind().connection.driver_connection)
    if any(done.values()):
        # A plain print, as 0038: said out loud, and no value in it.
        print("[0137] stored URL credentials removed: "
              + ", ".join(f"{k}={v}" for k, v in done.items() if v)
              + (" (rows listed under failed still carry one: see docs/17)"
                 if done["failed"] else ""))


def downgrade() -> None:
    # Deliberately a no-op: the credentials are kept nowhere, so there is
    # nothing to put back, and putting a victim's password back on the graph
    # is not a rollback. See the docstring.
    pass
