#!/usr/bin/env bash
# arm64 smoke test of the Unbound image under QEMU (docs/UNBOUND.md "arm64").
# Builds docker/unbound for linux/arm64, starts it with the static address the config expects,
# resolves a DNSSEC-signed name and requires the AD flag. Needs QEMU/binfmt for arm64
# (CI: docker/setup-qemu-action). Flaky/timeouts policy: QEMU is slow, so the query is retried
# up to ATTEMPTS times, DELAY seconds apart; only a result that never succeeds fails the run.
# Everything it creates is removed on exit.
set -euo pipefail

ATTEMPTS="${ATTEMPTS:-12}"
DELAY="${DELAY:-10}"
SUFFIX="$$"
IMAGE="dtk-unbound-arm64-${SUFFIX}"
NET="dtk-arm64-${SUFFIX}"
CTR="dtk-arm64-${SUFFIX}"

cleanup() {
  docker logs "$CTR" 2>&1 | tail -n 20 || true
  docker rm -f "$CTR" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker rmi -f "$IMAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker buildx build --platform linux/arm64 --load -t "$IMAGE" docker/unbound
docker network create --subnet 172.28.53.0/24 "$NET" >/dev/null
docker run -d --name "$CTR" --platform linux/arm64 --network "$NET" --ip 172.28.53.2 "$IMAGE" >/dev/null

arch="$(docker exec "$CTR" uname -m)"
[ "$arch" = "aarch64" ] || { echo "expected aarch64, got $arch"; exit 1; }

for i in $(seq 1 "$ATTEMPTS"); do
  out="$(docker exec "$CTR" drill -D -p 5353 @127.0.0.1 ietf.org A 2>&1 || true)"
  if grep -Eq '^;; flags:.* ad[ ;]' <<<"$out" && grep -q 'rcode: NOERROR' <<<"$out"; then
    echo "arm64 OK on attempt $i: NOERROR with AD"
    exit 0
  fi
  echo "attempt $i/$ATTEMPTS: no validated answer yet"
  sleep "$DELAY"
done
echo "$out"
echo "arm64 smoke test failed after $ATTEMPTS attempts"
exit 1
