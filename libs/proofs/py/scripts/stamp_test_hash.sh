#!/bin/sh
# Stamps the test digest on the public OpenTimestamps calendars and rewrites vectors/ots.json.
# The reference client is LGPL-3.0: it runs as an external tool and is never a dependency.
set -eu

OTS="${OTS:-uvx --from opentimestamps-client ots}"
ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

printf '%s' "The Fourth Official RFC 3161 test vector" > "$WORK/imprint"
$OTS stamp "$WORK/imprint"
$OTS info "$WORK/imprint.ots" > "$WORK/info"
cat "$WORK/info"

set --
for url in $(sed -n "s/.*PendingAttestation('\(.*\)').*/\1/p" "$WORK/info"); do
  set -- "$@" --calendar "$url"
done
VERSION="$($OTS --version 2>&1)"
cd "$ROOT" && uv run python libs/proofs/py/scripts/gen_ots_vectors.py \
  --pending "$WORK/imprint.ots" \
  --source "ots stamp (opentimestamps-client $VERSION), $(date -u +%Y-%m-%d), default public calendars" \
  "$@"
pnpm exec biome format --write libs/proofs/vectors/ots.json
