#!/bin/sh
# Same environment as deploy, but for the local dev server.
set -e
if [ -f .env.deploy ]; then
	set -a
	# shellcheck disable=SC1091
	. ./.env.deploy
	set +a
fi
exec cf dev "$@"
