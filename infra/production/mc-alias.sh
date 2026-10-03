# The root credential for `mc`, kept off its command line.
#
# SOURCED, never executed: the minio-init service mounts this file read-only
# at /mc-alias.sh and the backup command in README.md does the same, so it
# needs no execute bit (a repository authored on Windows records every file
# 100644, and a script that only ran with the bit set would not run).
#
# Why it exists (infra-10, 2026-10-03). `mc alias set local URL USER PASSWORD`
# puts the MinIO root password on mc's command line, and minio-init tries it
# up to sixty times while MinIO starts, on every `up`. Arguments are readable
# from the host's process list (/proc/<pid>/cmdline) for the life of the
# process, container or not, so any local account on the Docker host read the
# root credential of the evidence store without any privilege. mc's own
# `MC_HOST_<alias>` environment variable carries the same URL in the process
# environment instead, which only the same user and root can read.
#
# MEASURED against the pinned mc image, not assumed: mc does NOT percent-decode
# the credentials in an MC_HOST value. It takes them literally, so a password
# with an @, a slash, a hash, a percent sign or a space works as it stands and
# an encoded one is the wrong password. The one character it cannot carry is
# the colon, which separates the access key from the secret, so a root user or
# password with a colon is refused here by name rather than sent as a different
# credential. Generate both from a URL-safe alphabet (README, step 1), which
# never contains one.
#
# apps/api/tests/test_g48_image_context.py runs this file.

# Everything mc needs to reach MinIO, for this process and what it starts:
# the alias `local` with the root credential, and the certificate to trust.
# Nothing reaches a command line.
#
# mc reads extra certificate authorities from <config dir>/certs/CAs. The
# config dir is /tmp/.mc and not the default ~/.mc because /root in this image
# is mode 0550 and the container has no capabilities (cap_drop ALL in
# compose.yml), so root there cannot write to it; it can write /tmp.
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
