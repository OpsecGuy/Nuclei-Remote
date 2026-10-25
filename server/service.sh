#!/usr/bin/env bash
# Install and manage the Nuclei Remote systemd service on Ubuntu.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SCRIPT_PATH="$SCRIPT_DIR/service.sh"
SERVICE_NAME='nuclei-remote.service'
UNIT_FILE="/etc/systemd/system/$SERVICE_NAME"
MANAGED_MARKER='# Managed by Nuclei Remote service.sh'

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'HELP'
Usage: bash service.sh COMMAND [--user USERNAME]

  install     Generate the unit, enable startup at boot, and start/restart it.
  start       Start an installed service.
  stop        Stop the service.
  restart     Restart the service after configuration changes.
  status      Show the service status.
  logs        Follow the service journal (Ctrl+C to exit).
  uninstall   Stop, disable, and remove the systemd unit.
  help        Show this help.

Examples:
  bash service.sh install
  sudo bash service.sh install --user ubuntu
  bash service.sh restart
  bash service.sh uninstall

Installation requires an existing config.env and .venv with dependencies.
The service runs as the invoking user, or the user specified with --user.
Root callers without SUDO_USER must specify a non-root --user.
Administrative commands request sudo when necessary.
Uninstall keeps application files, config.env, results, and logs.
HELP
}

require_systemd() {
  [[ "$(uname -s)" == Linux ]] || die 'This helper requires Linux with systemd.'
  command -v systemctl >/dev/null || die 'systemctl was not found.'
  [[ -d /run/systemd/system ]] || die 'systemd is not running on this host.'
}

require_root() {
  if [[ "$EUID" -ne 0 ]]; then
    command -v sudo >/dev/null || die 'Run this command as root using --user for installation.'
    exec sudo -- /bin/bash "$SCRIPT_PATH" "$@"
  fi
}

check_existing_unit() {
  [[ ! -L "$UNIT_FILE" ]] || die "Refusing to change a symlink at $UNIT_FILE. Inspect it manually."
  if [[ -e "$UNIT_FILE" ]]; then
    [[ -f "$UNIT_FILE" ]] || die "Not a regular file: $UNIT_FILE"
    if ! grep -Fxq -- "$MANAGED_MARKER" "$UNIT_FILE"; then
      # Accept the earlier manually installed template for this same checkout.
      grep -Fxq 'Description=Nuclei Remote HTTP API' "$UNIT_FILE" &&
        grep -Fq -- "$SCRIPT_DIR/start.sh" "$UNIT_FILE" ||
        die "An unrelated unit already exists at $UNIT_FILE. Inspect it manually."
    fi
  fi
}

require_installed() {
  [[ -f "$UNIT_FILE" ]] || die 'Service is not installed. Run: bash service.sh install'
  check_existing_unit
}

install_service() {
  local service_user="$1" user_id temporary_unit
  service_user="${service_user:-${SUDO_USER:-}}"
  [[ -n "$service_user" ]] || die 'Specify a non-root service account with --user USERNAME.'
  [[ "$service_user" =~ ^[a-zA-Z_][a-zA-Z0-9_.-]*\$?$ ]] || die 'Invalid service account name.'
  user_id="$(id -u "$service_user")" || die "Unknown user: $service_user"
  [[ "$user_id" -ne 0 ]] || die 'Choose a regular account; the scanner must not run as root.'
  # Quoted systemd paths support spaces. Reject special expansion characters.
  [[ "$SCRIPT_DIR" =~ ^/[a-zA-Z0-9_./\ -]+$ ]] ||
    die 'The application path must contain only letters, digits, spaces, dots, slashes, underscores, or hyphens.'
  [[ -f "$SCRIPT_DIR/config.env" ]] || die 'Copy config.env.example to config.env and configure it first.'
  [[ -f "$SCRIPT_DIR/start.sh" && -f "$SCRIPT_DIR/server.py" ]] || die 'Application files are missing.'
  [[ -x "$SCRIPT_DIR/.venv/bin/python" ]] || die 'Create .venv and install requirements.txt first.'
  command -v runuser >/dev/null || die 'runuser was not found (provided by util-linux on Ubuntu).'
  runuser -u "$service_user" -- test -r "$SCRIPT_DIR/config.env" || die 'The service user cannot read config.env.'
  runuser -u "$service_user" -- test -r "$SCRIPT_DIR/start.sh" || die 'The service user cannot read start.sh.'
  runuser -u "$service_user" -- test -w "$SCRIPT_DIR" || die 'The service user needs write access to the server directory.'
  runuser -u "$service_user" -- "$SCRIPT_DIR/.venv/bin/python" -c 'import fastapi, uvicorn' ||
    die 'The service user cannot run the virtual environment or its dependencies are missing.'
  check_existing_unit
  temporary_unit="$(mktemp)"
  trap 'rm -f -- "${temporary_unit:-}"' EXIT
  cat > "$temporary_unit" <<UNIT
$MANAGED_MARKER
[Unit]
Description=Nuclei Remote HTTP API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$service_user
WorkingDirectory="$SCRIPT_DIR"
ExecStart=/bin/bash "$SCRIPT_DIR/start.sh"
Restart=on-failure
RestartSec=5
KillMode=control-group
TimeoutStopSec=10
UMask=0077
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT
  install -m 0644 -- "$temporary_unit" "$UNIT_FILE"
  rm -f -- "$temporary_unit"
  trap - EXIT
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME"
  systemctl restart "$SERVICE_NAME"
  if ! systemctl is-active --quiet "$SERVICE_NAME"; then
    systemctl --no-pager --full status "$SERVICE_NAME" || true
    die 'The service did not start. Check config.env and: bash service.sh logs'
  fi
  printf 'Installed and started %s as %s.\n' "$SERVICE_NAME" "$service_user"
  printf 'Check status: bash service.sh status\nFollow logs: bash service.sh logs\n'
}

uninstall_service() {
  check_existing_unit
  if [[ ! -f "$UNIT_FILE" ]]; then
    printf 'No local service unit found at %s. Nothing to remove.\n' "$UNIT_FILE"
    return
  fi
  systemctl disable --now "$SERVICE_NAME"
  rm -f -- "$UNIT_FILE"
  systemctl daemon-reload
  systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true
  printf 'Removed %s. Application files, configuration, results, and logs were kept.\n' "$SERVICE_NAME"
}

main() {
  local command="${1:-help}" service_user=''
  [[ "$#" -eq 0 ]] || shift
  if [[ "$command" == help || "$command" == --help || "$command" == -h ]]; then
    usage
    return
  fi
  case "$command" in install|start|stop|restart|status|logs|uninstall) ;; *) usage >&2; die "Unknown command: $command" ;; esac
  if [[ "$#" -gt 0 ]]; then
    [[ "$command" == install && "$#" -eq 2 && "$1" == --user && -n "$2" ]] || die 'Only install accepts --user USERNAME.'
    service_user="$2"
  fi
  require_systemd
  case "$command" in
    install)
      if [[ -n "$service_user" ]]; then
        require_root install --user "$service_user"
      else
        require_root install
      fi
      install_service "$service_user"
      ;;
    uninstall) require_root uninstall; uninstall_service ;;
    start|stop|restart) require_root "$command"; require_installed; systemctl "$command" "$SERVICE_NAME" ;;
    status) require_installed; systemctl --no-pager --full status "$SERVICE_NAME" ;;
    logs) require_root logs; require_installed; journalctl -u "$SERVICE_NAME" -n 50 -f ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
