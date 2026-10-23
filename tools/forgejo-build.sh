#!/usr/bin/env bash
# Run on the user's docker-build Forgejo runner, never a GitHub runner.
set -euo pipefail
revision="${SOURCE_REVISION:?SOURCE_REVISION is required}"
image="sideloop:review-${revision:0:12}"
tests="sideloop:tests-${revision:0:12}"
quality="sideloop:quality-${revision:0:12}"
mkdir -p output
cleanup() { docker image rm "$tests" "$quality" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker build --platform linux/amd64 -f tools/Dockerfile.quality -t "$quality" . 2>&1 | tee output/quality-build.log
docker run --rm --network none "$quality" 2>&1 | tee output/quality.log
docker build --platform linux/amd64 --build-arg BUILD_JOBS=4 \
  --label "org.opencontainers.image.revision=$revision" \
  --label org.opencontainers.image.source=https://github.com/shoyrock/sideloop \
  -t "$image" . 2>&1 | tee output/build.log
printf 'FROM %s\nCOPY tests/ /tests/\nCOPY tools/diagnose-auth.py /tools/diagnose-auth.py\n' "$image" > output/Dockerfile.tests
docker build -f output/Dockerfile.tests -t "$tests" .
docker run --rm --network none --entrypoint python3 "$tests" \
  -m unittest discover -s /tests -p 'test_*.py' -v 2>&1 | tee output/tests.log
docker run --rm --network none --add-host gsa.apple.com:127.0.0.1 \
  --entrypoint python3 "$tests" /tests/check_native_verification.py 2>&1 | tee output/native.log
SIDELOOP_SMOKE_IN_CONTAINER=1 python3 tests/smoke_container.py "$image" 2>&1 | tee output/smoke.log
python3 tests/smoke_anisette_v3.py "$image" 2>&1 | tee output/v3-smoke.log
docker image inspect "$image" > output/image-inspect.json
docker save "$image" | gzip -1 > output/sideloop-amd64.tar.gz
sha256sum output/sideloop-amd64.tar.gz > output/SHA256SUMS
printf '%s\n' "$revision" > output/source-revision.txt
