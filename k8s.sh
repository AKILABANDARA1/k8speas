#!/bin/bash

# Helper functions for output formatting
green() { echo -e "\e[32m$1\e[0m"; }
red() { echo -e "\e[31m$1\e[0m"; }
yellow() { echo -e "\e[33m$1\e[0m"; }

# Info about the container and environment
green "🔍 Kubernetes Pentest Recon Script"
green "=========================================================="
echo "📦 Container Info"
id
cat /etc/os-release
uname -a

# Container specifics
green "🚪 Environment Detection"
if [[ -f /.dockerenv ]]; then
    green "✅ Inside a Docker container."
elif [[ -f /proc/1/cgroup ]] && grep -q docker /proc/1/cgroup; then
    green "✅ Inside Docker (via cgroup)"
else
    red "❌ Not in a container."
fi

# Container File System
green "📂 Container File System"
echo "Overlay info (read-only filesystem):"
mount | grep overlay
echo "Writable paths:"
[ -w /tmp ] && green "✅ /tmp is writable" || red "❌ /tmp is not writable"
[ -w /dev/shm ] && green "✅ /dev/shm is writable" || red "❌ /dev/shm is not writable"

# Security Checks
green "🛡️ Security Controls"
echo "Privileged container check:"
if [[ "$(id -u)" -eq 0 ]]; then
    green "✅ Running as root inside the container"
else
    red "❌ Running as non-root inside the container"
fi

# Capabilities check
green "🛠️ Linux Capabilities"
capabilities=$(capsh --print | grep "Bounding set")
if [[ "$capabilities" == *"cap_sys_admin"* ]]; then
    green "✅ Container has sys_admin capability (privileged)"
else
    red "❌ No sys_admin capability"
fi

# Docker Socket Check
green "🗂️ Docker Socket Check"
if [[ -e /var/run/docker.sock ]]; then
    red "❌ Docker socket found — Potential for host escape"
else
    green "✅ No Docker socket found"
fi

# AppArmor and Seccomp Check
green "🔐 AppArmor / Seccomp"
if [[ ! -z "$(command -v apparmor_status)" ]]; then
    apparmor_status=$(apparmor_status | grep "enabled")
    if [[ ! -z "$apparmor_status" ]]; then
        green "✅ AppArmor is enabled"
    else
        red "❌ AppArmor not enabled"
    fi
else
    red "❌ AppArmor not found"
fi
seccomp_status=$(cat /proc/self/status | grep Seccomp)
if [[ ! -z "$seccomp_status" ]]; then
    green "✅ Seccomp enabled"
else
    red "❌ Seccomp not enabled"
fi

# SUID Binaries Check
green "🛠️ SUID Binaries"
find / -perm -4000 -type f 2>/dev/null

# Check for available escape tools
green "🔑 Escape Attempt Tools"
escape_tools=("nsenter" "chroot" "mount" "pivot_root" "fuser" "umount")
for tool in "${escape_tools[@]}"; do
    command -v $tool &>/dev/null && green "✔️ $tool available" || red "❌ $tool missing"
done

# Privilege Escalation via Kernel Exploits (Example: Host namespaces, /proc/self/root)
green "💡 Kernel Exploit Checks"
echo "Cgroup info:"
cat /proc/1/cgroup

echo "Check if we can pivot to host namespaces:"
nsenter -t 1 -m -u -i -n -p -w || red "❌ Unable to pivot namespaces (no nsenter)"
echo "Check if we can mount the host filesystem:"
mount -o bind / /mnt || red "❌ Unable to mount / (host fs) to /mnt"

# Check for writable /root (for host escape)
green "📂 Check for writable /rootfs"
if [ -w / ]; then
    green "✅ / (root filesystem) is writable"
else
    red "❌ / (root filesystem) is not writable"
fi

# Service Account Token Check (Service account token is the key for kube API access)
green "🔑 Service Account Token Check"
if [[ ! -f /var/run/secrets/kubernetes.io/serviceaccount/token ]]; then
    green "✅ No service account token mounted"
else
    red "❌ Service account token found"
fi

# Kubernetes API Access Test
green "🌐 Kubernetes API Access Test"
kubectl cluster-info &>/dev/null && green "✅ Kubernetes API reachable" || red "❌ Kubernetes API not reachable"

# Cloud Metadata Service Check
green "🌩️ Cloud Metadata Service Test"
if curl -s http://169.254.169.254/latest/meta-data/; then
    red "❌ Cloud metadata service reachable"
else
    green "✅ Cloud metadata service not reachable"
fi

# DNS Test
green "🧭 DNS Test"
if command -v dig &>/dev/null; then
    dig google.com &>/dev/null && green "✅ DNS resolution works" || red "❌ DNS lookup failed"
else
    red "❌ dig tool not found"
fi

# Kubernetes Secrets Check (if kubectl available)
green "🔑 Kubernetes Secrets Check"
if command -v kubectl &>/dev/null; then
    kubectl get secrets &>/dev/null && green "✅ Kubernetes secrets accessible" || red "❌ No access to Kubernetes secrets"
else
    red "❌ kubectl not installed"
fi

# Miscellaneous Useful Tools Check
green "🧰 Tools Installed"
for tool in curl wget nc bash python3 python socat nmap; do
    command -v $tool &>/dev/null && green "✔️ $tool found" || red "❌ $tool missing"
done

# Final Notes for Escape
green "💡 Manual Escape Suggestions"
echo "- Check for writable mounts: /proc, /rootfs"
echo "- Try `nsenter`, `chroot`, or `pivot_root` for escaping namespaces"
echo "- Check if you can mount /proc or /host into the container"
echo "- Look for the docker.sock file (can bind-mount to gain host access)"
green "=========================================================="
