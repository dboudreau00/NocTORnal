#!/bin/sh
# Postfix simple content filter that adds X-NocTORnal-Stamp (infra/production/mail-stamp/README.md).
#
# pipe(8) runs it as:   stamp-filter.sh -f sender -- recipient...
#
# The shape is Postfix's own simple filter (FILTER_README, "Simple content filter example"): save the
# message to a private file, run the signer over it, and give the result back to Postfix with its
# sendmail command, which delivers it. A message the signer cannot stamp comes back unchanged and is
# delivered, so the stamp never stops mail. A key the signer cannot use, a file it cannot write, or any
# other fault exits 75 (EX_TEMPFAIL): Postfix keeps the message in its deferred queue and tries again,
# rather than deliver it unstamped by accident.

# Localise these.
PYTHON=/usr/bin/python3
SIGNER=/usr/local/libexec/noctornal-stamp/mail_stamp_sign.py
KEY_FILE=/etc/noctornal-stamp/key
KEY_ID=mail:v1
# This server's name, as its milters write it in Authentication-Results.
AUTHSERV_ID=mx.corp.example
SPOOL=/var/spool/noctornal-stamp
# -G: the message is not a local submission. -i: a line holding only "." is not the end.
# NEVER add -t here: it would deliver to the addresses in the headers, not the envelope's.
SENDMAIL="/usr/sbin/sendmail -G -i"

EX_TEMPFAIL=75

umask 077
cd "$SPOOL" || { echo "$SPOOL does not exist"; exit $EX_TEMPFAIL; }
in=$(mktemp in.XXXXXXXXXX) || { echo "cannot create a file in $SPOOL"; exit $EX_TEMPFAIL; }
out="$in.stamped"
note="$in.note"
trap 'rm -f "$in" "$out" "$note"' 0
trap 'exit $EX_TEMPFAIL' 1 2 3 15

cat >"$in" || { echo "cannot save the message"; exit $EX_TEMPFAIL; }

# On a fault the signer's one line goes to standard output, which Postfix puts in the deferral's log
# line. A message left unstamped is logged through syslog where there is one.
if ! "$PYTHON" "$SIGNER" sign --authserv-id "$AUTHSERV_ID" --key-file "$KEY_FILE" \
        --key-id "$KEY_ID" <"$in" >"$out" 2>"$note"; then
    cat "$note"
    exit $EX_TEMPFAIL
fi
if [ -s "$note" ]; then
    logger -t noctornal-stamp -p mail.notice <"$note" 2>/dev/null || :
fi

$SENDMAIL "$@" <"$out"
exit $?
