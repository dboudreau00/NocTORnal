# The mail stamp: the signer on your mail server

NocTORnal reads the SPF, DKIM and DMARC results on an uploaded message only
when your own border mail server stamped it. The stamp is one header,
`X-NocTORnal-Stamp`, an HMAC-SHA256 under a key your mail server and the API
share and a sender does not hold. It covers the `Authentication-Results`
header your milters wrote, your server's own `Received` line, the message's
identity headers and its body (`docs/19` section 2.1 has the exact form).

Without it, every `Authentication-Results` header on an uploaded message is
the sender's claim: kept for the analyst to read, never recorded as a
verdict, and no domain is proposed from it. That is what an installation
with no key does, and it is deliberate: a sender writes a forged `Received`
line naming your server, and a forged `dkim=pass` above it, as easily as any
other header.

What it is not:

* It is not DKIM. It says your server saw these results on this message; it
  says nothing a DKIM signature does not already say about the sender.
* It does not cover mail your server never handled. A message forwarded from
  a victim organisation's mailbox carries their server's headers, not yours,
  and reads as the sender's claim.
* Hosted mail (Exchange Online, Google Workspace) runs no filter of yours,
  so it cannot stamp. Mail it delivers keeps the sender's-claim reading.

Postfix is the one worked example here. Any MTA that can pass a message
through a program after its milters, and take it back, can run the same
signer.

## The files

| File | Goes to |
|---|---|
| `scripts/mail_stamp_sign.py` | `/usr/local/libexec/noctornal-stamp/` on the mail server |
| `apps/api/src/noctornal_api/mail_stamp.py` | the same directory, beside it |
| `stamp-filter.sh` (this directory) | the same directory, mode 0755 |
| `postfix-master.cf.example` (this directory) | merged into `/etc/postfix/master.cf` |

The signer is Python 3.8 or later and the standard library only. It loads
`mail_stamp.py` from its own directory, so those two files are the whole of
it; the API verifies with the same module, so the two can never disagree on
the canonical form.

## Order matters: sign last

The filter must run **after** the milters that write
`Authentication-Results` (OpenDKIM, OpenDMARC, Rspamd and the like), and
nothing after it may change the body or a covered header (`From`,
`Reply-To`, `To`, `Cc`, `Subject`, `Date`, `Message-ID`, `In-Reply-To`,
`MIME-Version`, `Content-Type`, `Content-Transfer-Encoding`). A list footer,
a disclaimer, an 8-bit to 7-bit conversion after the stamp all make it fail
to verify, and the verdict is then read as the sender's claim. That fails
closed; it is still a verdict lost. A relay inside your organisation that
only adds its own `Received` or `Authentication-Results` lines above the
stamp is fine.

The signer stamps the topmost `Authentication-Results` header, and only when
it carries the authserv-id you give it (`AUTHSERV_ID` in `stamp-filter.sh`,
your milters' name for this server). A header a sender wrote with that name
is your server's to remove before its milters run, as RFC 8601 section 5
says. With Postfix, a `header_checks` line does it, and headers a milter
adds are not subject to `header_checks`. The signer reads the name without
regard to case or a trailing dot, so the line must drop those forms too:

```
# /etc/postfix/main.cf
header_checks = regexp:/etc/postfix/header_checks
# /etc/postfix/header_checks
/^Authentication-Results:[[:space:]]*mx\.corp\.example\.?([[:space:];]|$)/ IGNORE
```

It also removes every `X-NocTORnal-Stamp` a message arrives with before it
stamps: one from outside came from somebody without the key.

## The key

Make it once, with the production secrets (the same text goes in
`NOCTORNAL_MAIL_STAMP_KEY` in `secrets.env`, where `secrets.env.example`
explains the id and rotation):

```sh
python3 -c "import base64,secrets;print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

On the mail server, put that text in `/etc/noctornal-stamp/key`, owned
`root:noctornal-stamp`, mode `0640`. The signer refuses a key file anybody
else can read, or its group can write. A stolen key forges stamps, so it
lives only where the mail server already lives: the machine that writes
`Authentication-Results` is already the one you trust for them.

## Postfix, step by step

1. Create the user and the spool, on the mail server:

   ```sh
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin noctornal-stamp
   sudo install -d -o noctornal-stamp -g noctornal-stamp -m 0700 /var/spool/noctornal-stamp
   sudo install -d -o root -g root -m 0755 /usr/local/libexec/noctornal-stamp
   sudo install -d -o root -g noctornal-stamp -m 0750 /etc/noctornal-stamp
   ```

2. Copy the three files into `/usr/local/libexec/noctornal-stamp/`, and set
   `AUTHSERV_ID` and `KEY_ID` at the top of `stamp-filter.sh`.
3. Write the key file as above.
4. Check the signer by hand before Postfix runs it, with a message exported
   from a mailbox on this server:

   ```sh
   sudo -u noctornal-stamp python3 /usr/local/libexec/noctornal-stamp/mail_stamp_sign.py \
       sign --authserv-id mx.corp.example --key-file /etc/noctornal-stamp/key \
       --key-id mail:v1 < message.eml > stamped.eml
   sudo -u noctornal-stamp python3 /usr/local/libexec/noctornal-stamp/mail_stamp_sign.py \
       verify --key-file /etc/noctornal-stamp/key --key-id mail:v1 < stamped.eml
   ```

   `verify` prints one JSON line and exits 0 when the stamp verifies.
5. Merge `postfix-master.cf.example` into `/etc/postfix/master.cf`. The
   `-o content_filter` line goes on the `smtpd` that faces the internet and
   **never** in `main.cf`: the filter gives the message back through
   `sendmail`, and a `main.cf` filter would take it through again, for ever.
6. `sudo postfix check && sudo postfix reload`, then send one message to a
   single test mailbox and run `verify` on it as delivered before you rely
   on it.

What the filter does when something goes wrong:

* A message it cannot stamp (no `Authentication-Results`, none with your
  authserv-id on top, no `Received`) is delivered unchanged, with a line in
  the mail log. Mail never stops for want of a stamp.
* A key it cannot use, a spool it cannot write, any other fault: exit 75.
  Postfix keeps the message in the deferred queue and tries again, rather
  than deliver it unstamped by accident. `postqueue -p` shows them; the
  reason is in the mail log.

## Rotation

`secrets.env.example` has the steps: a new key under a new id on the mail
server first, then on the API with the old one kept in
`NOCTORNAL_MAIL_STAMP_KEY_RETIRED`, so mail stamped before still verifies
when it is parsed again. A key that leaked is removed at once and not
retired.
