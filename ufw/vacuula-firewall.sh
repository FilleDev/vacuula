#!/usr/bin/env bash
# Whitelist the Vacuula robot ports (Gen3 + Gen4) in ufw firewall
# Run as root:  sudo bash vacuula-firewall.sh
set -euo pipefail

# --- edit these ---------------------------------------------------------
ROBOT_IPS=("1.2.3.4")   # your home's public IP(s), space separated: ("1.2.3.4" "5.6.7.8")
GEN3_PORT=335
GEN4_PORT=3443
# ------------------------------------------------------------------------

TAG="vacuula-robots"

# Remove our previous rules
for n in $(ufw status numbered | grep "$TAG" | sed -E 's/^\[ *([0-9]+)\].*/\1/' | sort -rn); do
    ufw --force delete "$n"
done

for ip in "${ROBOT_IPS[@]}"; do
    ufw allow proto tcp from "$ip" to any port "$GEN3_PORT" comment "$TAG"
    ufw allow proto tcp from "$ip" to any port "$GEN4_PORT" comment "$TAG"
done

ufw status numbered | grep -E "$TAG|$GEN3_PORT|$GEN4_PORT" || true
