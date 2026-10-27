#!/usr/bin/env bash
# Installs the OPA command-line tool from its GitHub release into $HOME/bin.
# Usage: scripts/install-opa.sh [version]      (no version means the newest release)
# Needs the GitHub CLI ("gh") and, in GitHub Actions, GH_TOKEN set in the environment.
set -euo pipefail

version="${1:-}"
tag=""
if [ -n "$version" ]; then tag="v${version}"; fi

# OPA publishes one ready-to-run program per platform. This is the static Linux build.
asset="opa_linux_amd64_static"

mkdir -p "$HOME/bin" downloads

# $tag is deliberately unquoted: when empty it must vanish, which means "latest release".
if ! gh release download $tag --repo open-policy-agent/opa --pattern "$asset" \
     --dir downloads --clobber; then
  echo "Could not download '$asset' from open-policy-agent/opa (${tag:-latest}). Files in that release:"
  gh release view $tag --repo open-policy-agent/opa --json tagName,assets --jq '.tagName, (.assets[].name)'
  exit 1
fi

install -m 755 "downloads/$asset" "$HOME/bin/opa"
echo "$HOME/bin" >> "${GITHUB_PATH:-/dev/null}"
echo "Installed opa to $HOME/bin/opa"
