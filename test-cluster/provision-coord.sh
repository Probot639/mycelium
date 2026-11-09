#!/bin/bash
set -euo pipefail

echo "=== Coordinator provisioning ==="
source /vagrant/provision-base.sh

mkdir -p /opt/mycelium/{corpus,db}
chown -R vagrant:vagrant /opt/mycelium

# Build harness without ASAN for QEMU-mode fuzzing (ASAN shadow memory
# blows past node RAM under QEMU emulation). Build a second ASAN copy
# for crash triage only.
cd /vagrant/target
clang -g -O1 -o /opt/mycelium/vuln_parser vuln_parser.c
clang -g -O1 -fsanitize=address -o /opt/mycelium/vuln_parser_asan vuln_parser.c
echo "harness built: $(file /opt/mycelium/vuln_parser)"

# Coordinator systemd service (runs as vagrant, not root)
cat > /etc/systemd/system/mycelium-coord.service <<'SVC'
[Unit]
Description=Mycelium Coordinator
After=network.target

[Service]
Type=simple
User=vagrant
Environment=MYCELIUM_TOKEN=test-cluster-token
ExecStart=/usr/local/bin/mycelium spawn --listen 0.0.0.0:7100 --corpus /opt/mycelium/corpus --db /opt/mycelium/db/mycelium.db
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
SVC

systemctl daemon-reload
systemctl enable --now mycelium-coord.service
sleep 3

if ! systemctl is-active --quiet mycelium-coord.service; then
    echo "coordinator failed to start:"
    journalctl -u mycelium-coord.service --no-pager -n 20
    exit 1
fi
echo "coordinator running on 0.0.0.0:7100"

COORD_IP="10.10.10.10"

export MYCELIUM_TOKEN=test-cluster-token
mycelium inoculate \
    --coordinator http://127.0.0.1:7100 \
    --campaign vuln-parser \
    --harness /opt/mycelium/vuln_parser \
    --fuzzer aflpp \
    --seeds /vagrant/seeds \
    --triage-cmd '{harness} {file}' \
    -- afl-fuzz -Q -i '{corpus}' -o '{output}' -M main -F '{inject}' -- '{harness}' @@

echo "=== Campaign 'vuln-parser' ready. Nodes join at ${COORD_IP}:7100 ==="
