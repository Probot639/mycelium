#!/bin/bash
# Orchestrate the test cluster: bring up coord, then nodes, then start fuzzing.
set -euo pipefail
cd "$(dirname "$0")"

echo "=== Mycelium Test Cluster ==="
echo "Target: vuln_parser (MYC format parser with 3 planted bugs)"
echo "Topology: coord (.30) + node1 (.31) + node2 (.32)"
echo ""

# Step 1: Bring up coordinator (builds harness, creates campaign)
echo "[1/4] Starting coordinator..."
vagrant up coord
echo ""

# Step 2: Bring up fuzzer nodes (installs AFL++, but does not start fuzzing yet)
echo "[2/4] Starting fuzzer nodes..."
vagrant up node1 node2
echo ""

# Step 3: Start the fuzzer services
echo "[3/4] Starting fuzzers..."
vagrant ssh node1 -c "sudo systemctl start mycelium-node.service" 2>/dev/null
vagrant ssh node2 -c "sudo systemctl start mycelium-node.service" 2>/dev/null
echo "Fuzzers started on node1 and node2"
echo ""

# Step 4: Check status
echo "[4/4] Checking campaign status..."
sleep 5
vagrant ssh coord -c "MYCELIUM_TOKEN=test-cluster-token mycelium probe --coordinator http://127.0.0.1:7100 --nodes" 2>/dev/null

echo ""
echo "=== Cluster running ==="
echo ""
echo "Monitor:  vagrant ssh coord -c 'MYCELIUM_TOKEN=test-cluster-token mycelium probe --coordinator http://127.0.0.1:7100 --nodes'"
echo "Metrics:  vagrant ssh coord -c 'MYCELIUM_TOKEN=test-cluster-token mycelium metrics --coordinator http://127.0.0.1:7100 --campaign vuln-parser'"
echo "Logs n1:  vagrant ssh node1 -c 'journalctl -u mycelium-node -f'"
echo "Logs n2:  vagrant ssh node2 -c 'journalctl -u mycelium-node -f'"
echo "Stop:     vagrant destroy -f"
