#!/usr/bin/env bash
# Deploy aqua-timestamp to openwitness.org, from this machine, with no GitHub
# credentials on the server and no build load on it (2 vCPU, 4 GB, shared with the
# Matrix stack).
#
# What it does
#   1. Checks the tree is clean and HEAD is what origin/main has (only merged code
#      is deployed; --allow-unmerged is for a --build-only rehearsal).
#   2. Builds a context: `git archive HEAD` (exactly the commit, no .git) plus the
#      private aqua-rs-sdk source vendored from the local cargo checkout, with a
#      .cargo/config.toml that replaces only that git source. aqua-auth (public)
#      and the crates.io dependencies are fetched during the image build, pinned
#      by Cargo.lock (--locked).
#   3. Builds the image HERE (docker, which is podman on this host), stamping the
#      commit in as GIT_SHA (served at GET /version, and the OCI revision label),
#      and ships it with `docker save | docker load`.
#   4. Unless --build-only: keeps the previous image as :rollback-<date>, recreates
#      the container, waits for healthy, and checks that the PUBLIC /version names
#      the commit that was just built.
#
# Usage:  deploy/deploy.sh [--build-only] [--allow-unmerged] [--prepare-only] [--wipe-data]
#   --prepare-only   build the context locally and stop (prints its path)
#   --build-only     build, ship and tag the image, do not touch the service
#   --wipe-data      `docker compose down -v` first: DELETES the service's data volume
#                    (epochs, witnesses, leaderboard). Needed once, for the SDK 5.0.0
#                    wire change; never for a routine deploy.
#
# Env:    DEPLOY_SSH  ssh alias of the box (default agentic.inblock.io, port 8022)
#         PUBLIC_URL  where /version is checked (default https://openwitness.org)
#
# Rollback: ssh $DEPLOY_SSH 'docker tag aqua-timestamp:rollback-<date> aqua-timestamp:latest \
#             && cd /home/deploy/timestamps/deploy && docker compose up -d'
set -euo pipefail

DEPLOY_SSH=${DEPLOY_SSH:-agentic.inblock.io}
PUBLIC_URL=${PUBLIC_URL:-https://openwitness.org}
REMOTE_DEPLOY=/home/deploy/timestamps/deploy
SDK_GIT_PREFIX='git+https://github.com/inblockio/aqua-rs-sdk'

build_only=0 allow_unmerged=0 prepare_only=0 wipe_data=0
for a in "$@"; do
  case $a in
    --build-only) build_only=1 ;;
    --allow-unmerged) allow_unmerged=1 ;;
    --prepare-only) prepare_only=1 ;;
    --wipe-data) wipe_data=1 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

cd "$(git rev-parse --show-toplevel)"

# ---- 1. what is being deployed ------------------------------------------------
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "refusing: tracked files differ from HEAD (a deploy must be attributable to a commit)" >&2
  exit 1
fi
sha=$(git rev-parse HEAD)
git fetch -q origin main
if [ "$allow_unmerged" -eq 0 ] && [ "$sha" != "$(git rev-parse origin/main)" ]; then
  echo "refusing: HEAD $sha is not origin/main $(git rev-parse origin/main)" >&2
  echo "          merge first, or use --build-only --allow-unmerged to rehearse" >&2
  exit 1
fi
if [ "$allow_unmerged" -eq 1 ] && [ "$build_only" -eq 0 ] && [ "$prepare_only" -eq 0 ]; then
  echo "refusing: --allow-unmerged only makes sense with --build-only" >&2
  exit 1
fi
echo "deploying $sha"

# ---- 2. context ----------------------------------------------------------------
# Scratch lives under ~/.cache, never /tmp (tmpfs, RAM-backed on this host).
work=${XDG_CACHE_HOME:-$HOME/.cache}/aqua-timestamps-deploy
ctx=$work/ctx
rm -rf "$ctx" "$work/vendor-all"
mkdir -p "$ctx" "$work"
git archive HEAD | tar -x -C "$ctx"

# Vendor everything once (cargo reads its local git checkout, so this needs the
# developer's GitHub access, not the server's), then keep only the SDK crates.
config=$(cargo vendor --locked "$work/vendor-all" 2>/dev/null)
mkdir -p "$ctx/vendor" "$ctx/.cargo"
python3 - "$work/vendor-all" "$ctx/vendor" "$SDK_GIT_PREFIX" <<'PY'
import json, shutil, subprocess, sys
src, dst, prefix = sys.argv[1:4]
meta = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--format-version", "1", "--locked"]))
names = sorted({p["name"] for p in meta["packages"] if (p.get("source") or "").startswith(prefix)})
if not names:
    sys.exit("no package comes from " + prefix)
for n in names:
    shutil.copytree(f"{src}/{n}", f"{dst}/{n}")
print("vendored " + ", ".join(names), file=sys.stderr)
PY
# Keep only the stanza that replaces the SDK git source; crates.io stays live.
{
  printf '%s\n' "$config" | python3 -c '
import re, sys
prefix = sys.argv[1]
for block in re.split(r"\n(?=\[)", sys.stdin.read().strip()):
    if block.startswith("[source.\"" + prefix):
        print(re.sub(r"replace-with = .*", "replace-with = \"vendored-sdk\"", block))
' "$SDK_GIT_PREFIX"
  printf '\n[source.vendored-sdk]\ndirectory = "vendor"\n'
} > "$ctx/.cargo/config.toml"
grep -q 'vendored-sdk' "$ctx/.cargo/config.toml" && grep -q 'aqua-rs-sdk' "$ctx/.cargo/config.toml" \
  || { echo "could not write the SDK source replacement" >&2; exit 1; }
rm -rf "$work/vendor-all"
echo "context: $ctx"
[ "$prepare_only" -eq 1 ] && exit 0

# ---- 3. build here, ship the image ---------------------------------------------
# podman builds OCI images by default, which drops the HEALTHCHECK the compose
# file and the deploy wait rely on; ask for the docker format there.
fmt_build="" fmt_save=""
if docker --version 2>&1 | grep -qi podman; then
  fmt_build="--format docker"
  fmt_save="--format docker-archive"
fi
# shellcheck disable=SC2086
docker build $fmt_build --file "$ctx/deploy/Dockerfile" \
  --build-arg "GIT_SHA=$sha" --build-arg GIT_DIRTY=0 \
  --tag "aqua-timestamp:$sha" "$ctx"
built=$(docker image inspect "aqua-timestamp:$sha" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')
[ "$built" = "$sha" ] || { echo "image label $built != $sha" >&2; exit 1; }
# shellcheck disable=SC2086
docker save $fmt_save "aqua-timestamp:$sha" | gzip -1 | ssh "$DEPLOY_SSH" 'gunzip | docker load'
# podman names the image localhost/aqua-timestamp:<sha>; compose wants aqua-timestamp:<tag>.
ssh "$DEPLOY_SSH" "set -euo pipefail
  ref=\$(docker image ls --format '{{.Repository}}:{{.Tag}}' | grep ':$sha\$' | head -1)
  [ -n \"\$ref\" ] || { echo 'loaded image not found' >&2; exit 1; }
  docker tag \"\$ref\" aqua-timestamp:$sha
  docker image inspect aqua-timestamp:$sha --format 'on server: {{.Id}} revision={{index .Config.Labels \"org.opencontainers.image.revision\"}}'
"
[ "$build_only" -eq 1 ] && { echo "shipped aqua-timestamp:$sha to $DEPLOY_SSH; service untouched"; exit 0; }

# ---- 4. switch the service -----------------------------------------------------
scp -q "$ctx/deploy/docker-compose.yml" "$ctx/deploy/config.toml" "$DEPLOY_SSH:$REMOTE_DEPLOY/"
ssh "$DEPLOY_SSH" "set -euo pipefail
  rb=aqua-timestamp:rollback-\$(date +%Y%m%d)
  docker image inspect \"\$rb\" >/dev/null 2>&1 || docker tag aqua-timestamp:latest \"\$rb\" 2>/dev/null || true
  docker tag aqua-timestamp:$sha aqua-timestamp:latest
  cd $REMOTE_DEPLOY
  if [ $wipe_data -eq 1 ]; then
    echo 'WIPING the data volume (docker compose down -v)'
    docker compose down -v
  fi
  docker compose up -d
  for i in \$(seq 1 20); do
    if docker inspect --format='{{.State.Health.Status}}' timestamp 2>/dev/null | grep -q healthy; then
      echo \"container healthy after \$((i * 3))s\"; exit 0
    fi
    sleep 3
  done
  echo 'health check timed out'; docker logs --tail 30 timestamp; exit 1
"

# The proof: the public endpoint reports the commit that was just built.
live=$(curl -fsS --max-time 15 "$PUBLIC_URL/version")
echo "$live"
live_rev=$(printf '%s' "$live" | python3 -c 'import json,sys; print(json.load(sys.stdin)["revision"])')
if [ "$live_rev" != "$sha" ]; then
  echo "MISMATCH: $PUBLIC_URL/version says $live_rev, expected $sha" >&2
  exit 1
fi
echo "OK: $PUBLIC_URL/version == $sha"
