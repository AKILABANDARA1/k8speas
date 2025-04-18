#!/bin/bash

echo -e "\n🔍 Kubernetes Pentest Recon Script by 𝘌𝘹𝘱𝘦𝘳𝘵 𝘗𝘦𝘯𝘵𝘦𝘴𝘵𝘦𝘳"
echo "==========================================================="

# General system info
echo -e "\n📦 Container Info"
whoami
id
hostname
cat /etc/os-release 2>/dev/null
uname -a
ps aux --forest

# Check if running in a container
echo -e "\n🚪 Environment Detection"
grep -qa 'docker\|kubepods' /proc/1/cgroup && echo "✅ Running inside a container." || echo "❌ Not in a container."

# Check for Docker socket mount (escape vector)
echo -e "\n🔓 Docker Socket Mount Check"
[[ -S /var/run/docker.sock ]] && echo "⚠️ Docker socket is mounted!" || echo "✅ No Docker socket found."

# Host mount check
echo -e "\n🗂️ Host Mount Check"
mount | grep -E ' /host|/proc|/sys|/var' || echo "✅ No suspicious host mounts detected."

# Capabilities check
echo -e "\n🛠️ Linux Capabilities"
capsh --print 2>/dev/null || echo "capsh not found"

# Privileged container check
echo -e "\n🛡️ Privileged Container Check"
if [ "$(grep 'CapEff' /proc/$$/status | cut -d':' -f2 | tr -d ' ')" = "ffffffffffffffff" ]; then
  echo "⚠️ Full capabilities: likely a privileged container"
else
  echo "✅ Capabilities seem limited"
fi

# AppArmor / Seccomp
echo -e "\n🔐 AppArmor / Seccomp"
aa_status 2>/dev/null || echo "AppArmor not available"
grep Seccomp /proc/self/status

# Service Account token
echo -e "\n🔑 Service Account Token Check"
if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
  echo "⚠️ Service account token exists!"
  echo "Namespace: $(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)"
  echo -e "\n--- Token Snippet ---"
  head -c 100 /var/run/secrets/kubernetes.io/serviceaccount/token && echo "..."
else
  echo "✅ No service account token found."
fi

# Kubernetes API check
echo -e "\n🌐 Kubernetes API Access Test"
KUBE_HOST="${KUBERNETES_SERVICE_HOST:-kubernetes.default.svc}"
curl -s --connect-timeout 2 "https://$KUBE_HOST" || echo "❌ Kubernetes API not reachable from here."

# Check if curl can hit metadata server (cloud provider escape)
echo -e "\n🌩️ Cloud Metadata Service Test"
curl -s --connect-timeout 2 http://169.254.169.254 || echo "✅ No cloud metadata service reachable"

# Namespace/Pod info
echo -e "\n📦 Pod/Namespace Info"
[ -x "$(command -v kubectl)" ] && kubectl get pods -A 2>/dev/null || echo "kubectl not available inside container"

# Secrets enumeration
echo -e "\n🗝️ Kubernetes Secrets Check (if access exists)"
[ -x "$(command -v kubectl)" ] && kubectl get secrets -A 2>/dev/null || echo "No access or kubectl not present"

# DNS resolution
echo -e "\n🔎 DNS Test"
nslookup kubernetes.default.svc 2>/dev/null || dig kubernetes.default.svc || echo "DNS lookup failed"

# Auditd & Falco evasion checks
echo -e "\n🚨 Runtime Monitoring Detection"
pgrep -fl auditd
pgrep -fl falco

# File system checks
echo -e "\n🪓 Writable /tmp or /dev/shm (for payloads)"
for d in /tmp /dev/shm; do
  [ -w "$d" ] && echo "✅ Writable: $d" || echo "❌ Not writable: $d"
done

# Tools check
echo -e "\n🧰 Tools Installed"
for bin in curl wget nc bash python3 python socat nmap; do
  command -v $bin >/dev/null && echo "✔️ $bin found" || echo "❌ $bin missing"
done

# Escape attempt suggestion (manual)
echo -e "\n💡 Escape Attempt Suggestions (Manual)"
echo "- Check: nsenter, chroot, mount, pivot_root"
echo "- Try mapping host namespaces if allowed"
echo "- Try mounting /proc or /rootfs"
echo "- Check for writable docker.sock"

echo -e "\n✅ Enumeration complete. Time to dig deeper manually..."
