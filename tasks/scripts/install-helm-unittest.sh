#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 Hamster
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# The upstream plugin bundle is self-contained on all supported platforms.
# Pin both its release asset ID and published SHA256; never execute a partial
# download or fall back to an unverified archive.
HELM_UNITTEST_VERSION=1.2.1
HELM_UNITTEST_SHA256=bbcebd42631dff9fc595462fad839c49a1b06f9635e952e7e837d7e5fe82865f
HELM_UNITTEST_ASSET_API=https://api.github.com/repos/helm-unittest/helm-unittest/releases/assets/607406094

download_verified() {
  local archive=$1 expected=$2 actual url
  shift 2
  for url in "$@"; do
    if curl --fail --location --silent --show-error --proto '=https' \
      --connect-timeout 10 --max-time 120 --retry 2 --retry-delay 1 \
      --header 'Accept: application/octet-stream' --output "$archive" "$url"; then
      if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$archive" | awk '{print $1}')
      else
        actual=$(shasum -a 256 "$archive" | awk '{print $1}')
      fi
      if [ "$actual" != "$expected" ]; then
        echo 'Helm unittest archive checksum mismatch; refusing installation.' >&2
        return 1
      fi
      return 0
    fi
  done
  echo 'Unable to download the pinned Helm unittest archive.' >&2
  return 1
}

main() (
  work_dir=$(mktemp -d)
  trap 'rm -r "$work_dir"' EXIT
  download_verified "$work_dir/unittest.tgz" "$HELM_UNITTEST_SHA256" \
    "$HELM_UNITTEST_ASSET_API" \
    "https://github.com/helm-unittest/helm-unittest/releases/download/v${HELM_UNITTEST_VERSION}/unittest-${HELM_UNITTEST_VERSION}.tgz"
  # SHA256 above authenticates the immutable release bytes. The existing Helm
  # workflow does not install an upstream GPG key, so retain its signature mode.
  helm plugin install "$work_dir/unittest.tgz" --verify=false
)

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main
fi
