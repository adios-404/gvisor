#!/bin/bash
# Copies the logs of failed Bazel tests (and their runsc logs) into $1.

set -uo pipefail

out="${1:-ci-logs}"
cache="${BAZEL_CACHE:-${HOME}/.cache/bazel/}"
mkdir -p "${out}"

sudo find "${cache}" -path '*/testlogs/*' -name test.xml 2> /dev/null |
  while read -r xml; do
    if ! sudo grep -qE '<(failure|error)[ >]' "${xml}"; then
      continue
    fi
    dir="$(dirname "${xml}")"
    dest="${out}/${dir#*/testlogs/}"
    mkdir -p "${dest}"
    sudo cp "${dir}/test.log" "${xml}" "${dest}/" 2> /dev/null
    sudo cp -r "${dir}/test.outputs" "${dest}/" 2> /dev/null
    echo "failed: ${dir#*/testlogs/}"
  done

sudo chown -R "$(id -u):$(id -g)" "${out}"

# Why: runsc log names contain ':', which upload-artifact rejects, so upload
# one archive instead of the files.
tar -czf "${out}.tar.gz" "${out}"
rm -rf "${out}"
mkdir -p "${out}"
mv "${out}.tar.gz" "${out}/"
df -h / /mnt || true
