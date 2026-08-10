#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
CHART_DIR="$REPO_ROOT/deploy/helm/pgh-broker"
HELM_IMAGE="${HELM_IMAGE:-alpine/helm@sha256:c6d8088ddb279625a2e1ca3b08b22c18c946d1f65c8b810f28f1597435a1134c}"
DIGEST="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

helm() {
  docker run --rm --volume "$REPO_ROOT:/work:ro" --workdir /work "$HELM_IMAGE" "$@"
}

helm lint deploy/helm/pgh-broker --set-string "image.digest=$DIGEST"

if helm template pgh-broker deploy/helm/pgh-broker >/dev/null 2>&1; then
  echo "chart unexpectedly accepted a missing image digest" >&2
  exit 1
fi

rendered=$(helm template pgh-broker deploy/helm/pgh-broker \
  --namespace pgh-system \
  --values deploy/helm/pgh-broker/testdata/full.yaml)

grep -Fq "image: \"registry.example/pgh-broker@$DIGEST\"" <<<"$rendered"
grep -Fq "kind: Ingress" <<<"$rendered"
grep -Fq "kind: NetworkPolicy" <<<"$rendered"
grep -Fq "type: ClusterIP" <<<"$rendered"
grep -Fq "name: PGH_REPOSITORY_CACHE_TTL" <<<"$rendered"
grep -Fq "name: PGH_AUDIT_RETENTION" <<<"$rendered"
if grep -Fq "name: PGH_ALLOW_INSECURE_DATABASE" <<<"$rendered"; then
  echo "production manifest unexpectedly enables insecure database mode" >&2
  exit 1
fi
