#!/bin/sh
# Operator CLI entry point in the production image, installed as
# /usr/local/bin/asterism-cli. Dispatches to the compiled CLIs in dist/cli:
#
#   docker compose exec asterism-proxy asterism-cli deny-client list
#   docker compose exec asterism-proxy asterism-cli local-user add <username>
set -e

usage() {
  cat <<'EOF'
Usage: asterism-cli <command> [args...]

Commands:
  deny-client add <client_id-or-domain> [--reason <text>]
  deny-client remove <client_id-or-domain>
  deny-client list
  local-user add <username>          (prompts for the password; pipe it in with docker compose exec -T)
  local-user deactivate <username>
  local-user list
  local-user set-admin <username> on|off
  resource-server list
  resource-server show <identifier>
  resource-server approve <identifier> [--name X] [--internal] [--release-claims a,b]
  resource-server set <identifier> [--name X] [--release-claims a,b] [--enable|--disable] [--internal|--no-internal]
  resource-server policy <identifier> <scope> [--short-lived|--no-short-lived]
                         [--require-groups a,b|--no-require-groups] [--description X|--no-description]
  resource-server refresh <identifier>
  resource-server remove <identifier>   (revokes every grant and refresh token; set --disable is reversible)
  rotate-signing-key
EOF
}

case "$1" in
  deny-client | local-user | resource-server | rotate-signing-key)
    cmd="$1"
    shift
    # Absolute path: exec -w can change the working directory.
    exec node "/app/dist/cli/$cmd.js" "$@"
    ;;
  help | -h | --help)
    usage
    ;;
  *)
    [ -n "$1" ] && echo "asterism-cli: unknown command: $1" >&2
    usage >&2
    exit 1
    ;;
esac
