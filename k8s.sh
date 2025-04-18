#!/bin/bash

# Colors
green() { echo -e "\e[32m$1\e[0m"; }
red()   { echo -e "\e[31m$1\e[0m"; }
yellow(){ echo -e "\e[33m$1\e[0m"; }

separator() {
  echo -e "\n\e[34m🔹─────────────────────────────────────────────────────────────🔹\e[0m\n"
}

banner() {
  echo -e "\n\e[1;36m🚀 Kubernetes Pentest Recon Script v2 — by AkilerrrrrR 🧠\e[0m"
  echo -e "\e[1;36m===============================================================\e[0m\n"
}

banner

############################################################
# 📦 CONTAINER / ENVIRONMENT INFO
############################################################
separator
green "📦 Container Environment Info"
id
cat /etc/os-release
uname -a

############################################################
# 🚪 CONTAINER ENVIRONMENT DETECTION
############################################################
separator
green "🚪 Environment Detection"
[[ -f /.dockerenv ]] && green "✅ Inside a Docker container." || yellow "⚠️ Possibly not Docker (checking cgroup)"
grep -q docker /proc/1/cgroup && green "✅ Docker cgroup detected." || red "❌ Not in Docker (via cgroup)"

############################################################
# 📂 FILESYSTEM & MOUNTS
############################################################
separator
green "📂 Filesystem & Writable Mounts"
mount | grep overlay
[ -w /tmp ] && green "✅ /tmp is writable" || red "❌ /tmp is not writable"
[ -w /dev/shm ] && green "✅ /dev/shm is writable" || red "❌ /dev/shm is not writable"
mount | grep -E '/host|/rootfs|/etc/hostname|/etc/kubernetes'

############################################################
# 🛡️ SECURITY CONTROLS & CAPABILITIES
############################################################
separator
green "🛡️ Security Controls"
[ "$(id -u)" -eq 0 ] && green "✅ Running as root" || red "❌ Not running as root"

capsh --print | grep "Bounding set" | grep -q cap_sys_admin && green "✅ cap_sys_admin present" || red "❌ No cap_sys_admin"

[ -e /var/run/docker.sock ] && red "❌ Docker socket exposed!" || green "✅ No Docker socket"

[[ -x "$(command -v apparmor_status)" ]] && apparmor_status=$(apparmor_status | grep "enabled") && green "✅ AppArmor enabled" || red "❌ AppArmor not found or disabled"
grep -q Seccomp /proc/self/status && green "✅ Seccomp enabled" || red "❌ Seccomp not enabled"

############################################################
# 🔑 ESCAPE TOOLS CHECK
############################################################
separator
green "🔑 Escape Tools & SUID Binaries"
for tool in nsenter chroot mount pivot_root fuser umount; do
    command -v $tool &>/dev/null && green "✔️ $tool found" || red "❌ $tool missing"
done
find / -perm -4000 -type f 2>/dev/null

############################################################
# 💡 ESCAPE / HOST ENUMERATION ATTEMPTS
############################################################
separator
green "💡 Host Escape Checks"
cat /proc/1/cgroup
ls -l /proc/1/ns
nsenter -t 1 -m -u -i -n -p -w &>/dev/null && red "❌ Host namespace pivot worked!" || green "✅ Namespace isolation intact"
mount -o bind / /mnt &>/dev/null && red "❌ Able to bind host root to /mnt" || green "✅ Cannot bind host root"

[ -w / ] && green "✅ / is writable" || red "❌ Root filesystem is read-only"

############################################################
# 🔐 SERVICE ACCOUNT & KUBERNETES API ACCESS
############################################################
separator
green "🔐 Kubernetes Service Account Info"
SA_PATH="/var/run/secrets/kubernetes.io/serviceaccount"
if [[ -f "$SA_PATH/token" ]]; then
    green "✅ Service account mounted"
    echo "Namespace: $(cat $SA_PATH/namespace)"
    echo "Token (first 50 chars): $(head -c 50 $SA_PATH/token)..."
    openssl x509 -in $SA_PATH/ca.crt -text -noout | grep Subject
else
    green "✅ No service account token mounted"
fi

green "🌐 Kubernetes API Access Test"
kubectl cluster-info &>/dev/null && green "✅ Kubernetes API reachable" || red "❌ API not reachable"
kubectl get secrets &>/dev/null && green "✅ Secrets accessible" || red "❌ Cannot access secrets"
kubectl get pods -A -o wide &>/dev/null && green "✅ Pod listing possible" || red "❌ Pod enumeration blocked"

############################################################
# ☁️ CLOUD METADATA SERVICES
############################################################
separator
green "☁️ Cloud Metadata Detection"
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/ && red "❌ GCP Metadata reachable"
curl -s http://169.254.169.254/metadata/instance?api-version=2021-02-01 -H Metadata:true && red "❌ Azure Metadata reachable"
curl -s http://169.254.169.254/latest/dynamic/instance-identity/document && red "❌ AWS Metadata reachable"

############################################################
# 🧬 ENV VARS, SSH, HISTORY
############################################################
separator
green "🧬 Environment & Secrets Discovery"
env | grep -iE "token|key|secret|pass" || green "✅ No obvious secrets in ENV"

green "🔑 SSH Keys and Configs"
find / -name "id_rsa" -o -name "authorized_keys" 2>/dev/null

green "📜 History Files"
find / -name ".*history" 2>/dev/null

############################################################
# 📄 KUBECONFIG, KUBELET, ETC
############################################################
separator
green "📄 Kubelet & kubeconfig Discovery"
find / -name "kubeconfig" -o -name "config" -path "*/.kube/*" 2>/dev/null
ls -la /etc/kubernetes 2>/dev/null
ls -la /var/lib/kubelet 2>/dev/null

############################################################
# 📡 KUBELET EXPLOIT ATTEMPTS
############################################################
separator
green "📡 Kubelet Service Checks"
curl -k https://localhost:10250/metrics &>/dev/null && red "❌ kubelet metrics exposed"
curl -k https://localhost:10250/pods &>/dev/null && red "❌ kubelet pods endpoint exposed"

############################################################
# 🧭 NETWORK & DNS
############################################################
separator
green "🧭 DNS & Networking"
command -v dig &>/dev/null && dig google.com &>/dev/null && green "✅ DNS works" || red "❌ DNS broken"
for port in 80 443 10250; do
    timeout 1 bash -c "cat < /dev/null > /dev/tcp/127.0.0.1/$port" &>/dev/null && red "❌ Port $port open on localhost" || green "✅ Port $port closed"
done

############################################################
# 🧰 TOOLSET CHECK
############################################################
separator
green "🧰 Tools Installed"
for tool in curl wget nc bash python3 python socat nmap dig nsenter; do
    command -v $tool &>/dev/null && green "✔️ $tool found" || red "❌ $tool missing"
done

############################################################
# 🧨 FINAL NOTES & EXPLOIT SUGGESTIONS
############################################################
separator
green "🧨 Final Manual Suggestions"
cat <<EOF
- Try bind mounting /host or /proc if accessible.
- Upload and run escape exploits (dirty pipe, dirty cow, etc.).
- Check service account token against API access: kubectl auth can-i --list
- If Docker/Containerd socket is exposed, use mounting/privileged container trick.
- Use kubectl proxy or kubelet ports for SSRF or RCE.
- Pivot to adjacent containers via shared mounts or cloud metadata access.
EOF
separator
green "🎯 Done — Recon complete!"
