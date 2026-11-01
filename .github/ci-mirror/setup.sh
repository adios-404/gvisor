#!/bin/bash
# Prepares a GitHub-hosted runner the way .buildkite/hooks/pre-command
# prepares a Buildkite agent. Prints the exports for $GITHUB_ENV.

set -euxo pipefail

# Why: the runner has about 14 GB free, and a gVisor Bazel cache needs more.
sudo rm -rf /usr/share/dotnet /usr/local/lib/android /opt/ghc \
  /opt/hostedtoolcache /usr/local/share/boost /usr/local/.ghcup
sudo docker image prune -af > /dev/null || true

# Use the temporary disk for the Bazel cache when it has more room.
bazel_cache="${HOME}/.cache/bazel/"
if [[ -d /mnt ]] && (( $(df --output=avail -B1G /mnt | tail -1) > 40 )); then
  sudo mkdir -p /mnt/bazel-cache
  sudo chown "$(id -u):$(id -g)" /mnt/bazel-cache
  bazel_cache="/mnt/bazel-cache/"
fi
df -h / /mnt >&2 || true

export DEBIAN_FRONTEND=noninteractive
sudo -E apt-get update -q
sudo -E apt-get install -qy make linux-libc-dev graphviz jq curl binutils \
  gnupg gcc pkg-config ca-certificates rsync kmod unzip
if apt-cache show "linux-headers-$(uname -r)" > /dev/null 2>&1; then
  sudo -E apt-get install -qy "linux-headers-$(uname -r)"
fi

# Why: the tests run in a Docker container, and the test runner raises
# RLIMIT_NOFILE to 131072 (ping_socket_test, pipe_test). The runner's Docker
# default hard limit is lower, so those tests fail with EPERM or EMFILE.
daemon_json=/etc/docker/daemon.json
[[ -s "${daemon_json}" ]] || echo '{}' | sudo tee "${daemon_json}" > /dev/null
jq '. + {"default-ulimits": {"nofile": {"Name": "nofile", "Hard": 1048576, "Soft": 1048576}}}' \
  "${daemon_json}" | sudo tee "${daemon_json}.new" > /dev/null
sudo mv "${daemon_json}.new" "${daemon_json}"
sudo systemctl restart docker
cat "${daemon_json}" >&2

# Why: /dev/kvm is root:kvm 0660 on the runner, and the tests run as the
# runner user, so the KVM platform tests cannot open it without this rule.
if [[ -e /dev/kvm ]]; then
  echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' |
    sudo tee /etc/udev/rules.d/99-kvm4all.rules
  sudo udevadm control --reload-rules
  sudo udevadm trigger --name-match=kvm
  ls -l /dev/kvm >&2
else
  echo "::warning::/dev/kvm is missing, so the KVM platform tests will fail."
fi

# The same sysctls as the Buildkite hook.
sudo sysctl -w kernel.dmesg_restrict=0
if [[ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2> /dev/null)" == "1" ]]; then
  sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
fi
sudo sysctl -w kernel.print-fatal-signals=1

echo "BAZEL_CACHE=${bazel_cache}" >> "${GITHUB_ENV}"
