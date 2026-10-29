# The root credential for `mc`, kept off its command line.
#
# Sourced, never executed: minio-init and the README's backup command mount it read-only, so it
# needs no execute bit (a repository authored on Windows records every file 100644). A command
# line argument is readable from /proc/<pid>/cmdline by any local account on the host, container
# or not; mc's MC_HOST_<alias> carries the same URL in the process environment, which only the
# same user and root can read.
#
# mc takes the credentials in an MC_HOST value literally, without percent-decoding: @, /, #, %
# and spaces work as they stand, and an encoded password is the wrong one. A colon separates the
# access key from the secret, so a root user or password holding one is refused by name rather
# than sent as a different credential. Generate both from a URL-safe alphabet (README, step 1).
# A test runs this file.

# Sets up mc for this process and what it starts: the alias `local` with the root credential,
# and MinIO's certificate in <config dir>/certs/CAs. The config dir is /tmp/.mc, not ~/.mc,
# because /root in this image is mode 0550 and, with every capability dropped, root cannot
# write there.
mc_setup() {
  case "$MINIO_ROOT_USER$MINIO_ROOT_PASSWORD" in
    *:*)
      echo "mc-alias: MINIO_ROOT_USER and MINIO_ROOT_PASSWORD must not contain a colon;" >&2
      echo "mc-alias: mc reads them from a URL, where a colon ends the access key. Choose" >&2
      echo "mc-alias: new values in secrets.env and start MinIO again." >&2
      return 1
      ;;
  esac
  # Both locations can be overridden, for the test that runs this file on a
  # host that has neither /tmp/.mc nor /certs; in the container neither is set.
  MC_CONFIG_DIR="${MC_CONFIG_DIR:-/tmp/.mc}"
  export MC_CONFIG_DIR
  mkdir -p "$MC_CONFIG_DIR/certs/CAs"
  cp "${MC_CERTIFICATE:-/certs/public.crt}" "$MC_CONFIG_DIR/certs/CAs/minio.crt"
  MC_HOST_local="https://${MINIO_ROOT_USER}:${MINIO_ROOT_PASSWORD}@minio:9000"
  export MC_HOST_local
}
