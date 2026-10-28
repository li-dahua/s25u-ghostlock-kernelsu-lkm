#!/usr/bin/env bash
# s25u-ksu-lkm / recover-root.sh
# 重启后一键恢复 S25U 的内存态 root（CVE-2026-43499 + prelink + insmod kernelsu.ko）
# 用法: bash recover-root.sh [serial]
set -uo pipefail

SER="${1:-R5CY12Y97GV}"
ADB="adb -s $SER"
WORK="${WORK:-/tmp}"
PATCHED="${WORK}/kernelsu-patched.ko"     # UND 版本（未 prelink）
PRELINK="${WORK}/prelink.py"
OUT="${WORK}/kernelsu-abs.ko"
KS="${WORK}/kallsyms-$(date +%s).txt"

say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m!! %s\033[0m\n' "$*" >&2; exit 1; }

# 0) 等设备
say "等待设备 $SER"
for i in $(seq 1 60); do
  if $ADB get-state >/dev/null 2>&1; then break; fi
  sleep 2
done
$ADB get-state >/dev/null 2>&1 || die "设备不在线（插 USB / 开 USB 调试 / 选 MTP）"

say "设备状态"
$ADB shell 'uptime; getprop ro.build.version.release' || true

# 1) 起 exploit + root daemon
say "启动 exploit (CVE-2026-43499)"
$ADB shell 'ls -la /data/local/tmp/cve-2026-43499 /data/local/tmp/cve-2026-43499-root 2>&1' || true
$ADB shell 'nohup /data/local/tmp/cve-2026-43499 >/data/local/tmp/exploit.out 2>&1 &' || true
sleep 6

say "测试 root 通道"
ROOT_OK=0
for i in $(seq 1 20); do
  out=$($ADB shell 'echo "id" | /data/local/tmp/cve-2026-43499-root' 2>&1)
  if echo "$out" | grep -q 'uid=0'; then echo "$out"; ROOT_OK=1; break; fi
  sleep 2
done
[ "$ROOT_OK" = 1 ] || die "root 通道没起来：$out"

# 2) 放开 kptr + 导出 kallsyms（本次 boot 的 KASLR 布局）
say "导出 /proc/kallsyms"
$ADB shell 'echo "echo 0 > /proc/sys/kernel/kptr_restrict; echo dumped" | /data/local/tmp/cve-2026-43499-root'
$ADB shell 'cat /proc/kallsyms' > "$KS" 2>/dev/null
[ -s "$KS" ] || die "kallsyms 导出失败"
echo "   -> $KS ($(wc -l < "$KS") 行)"

# 3) 重新 prelink（每次 boot KASLR 不同，必须重做）
say "prelink .ko -> SHN_ABS"
[ -f "$PATCHED" ] || die "缺 $PATCHED"
[ -f "$PRELINK" ] || die "缺 $PRELINK"
python3 "$PRELINK" "$PATCHED" "$KS" "$OUT" || die "prelink 失败"
ls -la "$OUT"

# 4) 推上去并 insmod
say "insmod"
$ADB push "$OUT" /data/local/tmp/kernelsu-abs.ko >/dev/null || die "push 失败"
$ADB shell 'echo "rmmod kernelsu 2>/dev/null; insmod /data/local/tmp/kernelsu-abs.ko; echo insmod_rc=\$?; lsmod | grep -i kernelsu" | /data/local/tmp/cve-2026-43499-root'

# 5) SELinux 放行（exploit 上下文是 u:r:kernel:s0，DEFEX 会挡部分路径）
say "setenforce 0 + 校验"
$ADB shell 'echo "setenforce 0; getenforce; id" | /data/local/tmp/cve-2026-43499-root'

say "完成。打开 KernelSU 管理器应显示「工作中 <LKM>」"
say "下一步：启动 NeoZygisk monitor（TMP_PATH=/dev/nz 实验）+ 软重启 zygote"
