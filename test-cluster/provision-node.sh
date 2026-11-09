#!/bin/bash
set -euo pipefail

NODE_NAME="$(hostname)"
echo "=== Node ${NODE_NAME} provisioning ==="
source /vagrant/provision-base.sh

mkdir -p "/opt/mycelium/workdir-${NODE_NAME}"
chown -R vagrant:vagrant /opt/mycelium

COORD_IP="10.10.10.10"

cat > /etc/systemd/system/mycelium-node.service <<SVC
[Unit]
Description=Mycelium Fuzzer Node (${NODE_NAME})
After=network.target

[Service]
Type=simple
User=vagrant
Environment=MYCELIUM_TOKEN=test-cluster-token
Environment=AFL_SKIP_CPUFREQ=1
Environment=AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
Environment=AFL_NO_UI=1
ExecStart=/usr/local/bin/mycelium join \\
    --coordinator http://${COORD_IP}:7100 \\
    --campaign vuln-parser \\
    --workdir /opt/mycelium/workdir-${NODE_NAME}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SVC

systemctl daemon-reload
systemctl enable mycelium-node.service

echo "=== Node ${NODE_NAME} ready ==="
echo "Start fuzzing: systemctl start mycelium-node.service"
