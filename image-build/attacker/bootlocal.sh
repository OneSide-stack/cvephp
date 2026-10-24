#!/bin/sh
# TinyCore runs this as root during boot. No default route or DNS is installed.
killall udhcpc 2>/dev/null || true
ip link set eth0 up 2>/dev/null || ifconfig eth0 up
ip addr flush dev eth0 2>/dev/null || true
ip addr add 192.168.10.10/24 dev eth0 2>/dev/null || ifconfig eth0 192.168.10.10 netmask 255.255.255.0
ip route del default 2>/dev/null || true
grep -q 'assessment-target' /etc/hosts || echo '192.168.10.55 assessment-target' >>/etc/hosts
: >/etc/resolv.conf

mkdir -p /home/tc/lab-evidence
chown -R tc:staff /home/tc/lab-evidence /home/tc/lab 2>/dev/null || chown -R tc:tc /home/tc/lab-evidence /home/tc/lab 2>/dev/null || true
PY="$(command -v python3 || command -v python3.6 || true)"
if ! command -v python3 >/dev/null 2>&1 && command -v python3.6 >/dev/null 2>&1; then
  ln -sf "$(command -v python3.6)" /usr/local/bin/python3
  PY="$(command -v python3)"
fi
if [ -n "$PY" ] && ! pidof range_proxy.py >/dev/null 2>&1; then
  if [ "$(id -u)" -eq 0 ]; then
    su tc -c "nohup $PY /home/tc/lab/range_proxy.py >/tmp/range-proxy.log 2>&1 &"
  else
    nohup "$PY" /home/tc/lab/range_proxy.py >/tmp/range-proxy.log 2>&1 &
  fi
fi
# Wait for a real bound management socket, not a fixed readiness timer.
n=0
while [ "$n" -lt 30 ]; do
  if wget -q -O /tmp/range-proxy-ready.json http://127.0.0.1:8081/api/state 2>/dev/null; then break; fi
  n=$((n+1)); sleep 1
done

# This only records boot-script completion. The controller separately requires
# labctl's address, proxy, X process, and X socket checks before reporting Ready.
printf 'CYBER_RANGE_ATTACKER_BOOT address=192.168.10.10 proxy=%s\n' \
  "$(test -s /tmp/range-proxy-ready.json && echo running || echo failed)"
