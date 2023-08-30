#!/usr/bin/env bash

set -euxo pipefail

SCRIPT_DIR="$(cd -P -- "$(dirname "$0")" && pwd -P)"
DOCS_DIR="$(cd -P -- "${SCRIPT_DIR}/../../docs" && pwd -P)"

docker run --rm -it --name jekyll \
  -p "127.0.0.1:4000:4000" \
  -v "${DOCS_DIR}:/srv/jekyll:Z" \
  jekyll/jekyll:3.8 \
  jekyll serve
