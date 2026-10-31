#!/bin/sh
# Sources .env.deploy (gitignored) and forwards every argument to `cf deploy`,
# e.g. `npm run deploy -- --secrets-file .env.production`.
set -e
if [ -f .env.deploy ]; then
	set -a
	# shellcheck disable=SC1091
	. ./.env.deploy
	set +a
fi
exec cf deploy "$@"
