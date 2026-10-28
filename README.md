# S25U (SM-S9380) — KernelSU via LKM + memory-only root

Galaxy S25 Ultra（SM-S9380，国行 `S9380ZHSDCZH1`，Android 16 / SDK 36，内核 `6.6.98-android15-8-pd6ff1cd-abogkiS9380ZHSDCZH1-4k`）在 **bootloader 锁死、不能刷机** 的前提下，拿到 **KernelSU（LKM 模式）** 的完整流程与踩坑记录。

> 重启 = 全部丢失（root、KSU、模块）。这是纯内存态方案。

---

## 1. 总体思路

```
CVE-2026-43499 exploit (pselect 竞态)  →  临时 root (uid=0, u:r:kernel:s0)
        ↓
读 /proc/kallsyms → prelink kernelsu.ko（UND → SHN_ABS 运行时地址）
        ↓
insmod kernelsu-abs.ko → KernelSU 管理器显示「工作中 <LKM> 32525-2」
        ↓
SELinux 回到 Enforcing → 用 roothelper 模块（customize.sh 里 setenforce 0）恢复 Permissive
```

关键点：**不能用官方发布的内核模块**，必须针对本机 `.config` 自己编译，并且每次开机重新 prelink（KASLR slide 每次不同）。

---

## 2. 目录结构

```
tools/    符号/CRC/BTF 分析与 prelink 工具
  btfdiff.py    BTF 结构体交叉比对（设备 /sys/kernel/btf/vmlinux vs 本地 vmlinux）
  crccheck.py   从设备 Image 反推 __ksymtab/__kcrctab，比对 .ko 的 __versions CRC
  patchko.py    直接改写 .ko 的 CRC 表
  prelink.py    **核心**：把 UND 符号改成 SHN_ABS + 运行时地址（跳过 CRC + 绕过导出缺失）
  vers.py       导出 .ko 的 __versions 清单
modules/
  roothelper/  自制 KSU 模块：以 u:r:ksu:s0 执行 setenforce 0，恢复 Permissive
  roothelper.zip
scripts/
  root-recover-usb.sh   USB 版：重启 → 等 uptime ≥110s → 单发 exploit → 轮询（最多 6 轮）
  root-loop-wifi2.sh    无线版：扫端口 + 轮换 STACK_WRITER_DELAY_USEC
  recover-root.sh       单次恢复 + 后续 insmod 流程
  exploit-loop.sh       早期版本（USB，已弃用）
notes/       当日完整攻关日志（原始记录）
build/       编译说明（见 build/README.md）
```

---

## 3. 完整步骤

### 3.1 拿临时 root

```bash
adb shell "CVE43499_ROOT_HELPER=/data/local/tmp/cve-2026-43499-root \
  STACK_WRITER_DELAY_USEC=25000 \
  LD_PRELOAD=/data/local/tmp/preload.so /system/bin/id"
```

成功日志特征：

```
pipe physrw ... done=1 root=1 read_ok=1 write_ok=1 rw64=1/1 uid=2000->0
exploit completed attempt=N/24
```

失败特征：`window=0` + `refusing retry on this boot`（本 boot 只有一次机会，需重启重来）。

- `preload.so` = 上游 `cve-2026-43499-app.so` 改名
- `cve-2026-43499`（driver）单独跑会 SIGSEGV，必须由 `LD_PRELOAD` 加载
- `STACK_WRITER_DELAY_USEC=25000` 是实测唯一稳定命中过的值

### 3.2 prelink 内核模块（每次开机必做）

```bash
# 设备侧：导出 kallsyms
echo 0 > /proc/sys/kernel/kptr_restrict
cat /proc/kallsyms > /data/local/tmp/ks_new.txt
adb pull /data/local/tmp/ks_new.txt

# 主机侧：重写 UND 符号
python3 tools/prelink.py kernelsu-patched.ko ks_new.txt kernelsu-abs.ko
# → prelinked=214 unresolved=0

adb push kernelsu-abs.ko /data/local/tmp/
adb shell '<root> insmod /data/local/tmp/kernelsu-abs.ko'
adb shell 'lsmod | grep kernelsu'   # kernelsu 172032 0
```

`prelink.py` 做的事：解析 `kallsyms`，把 `.ko` 里所有 **UND** 符号直接改成 `SHN_ABS` + 运行时绝对地址。内核 `simplify_symbols()` 对 `SHN_ABS` 不做重定位、**也不做 CRC 校验**，从而同时解决两个问题：

1. 本机内核只导出 13020 个符号，KSU 需要的 64 个（59 函数 + 5 数据）没导出；
2. `__versions` 里有 21 项 CRC 对不上。

### 3.3 恢复 Permissive

KSU 一加载 SELinux 就回 Enforcing，exploit 的 root socket 立刻失效。解法：装 `modules/roothelper.zip`（KSU 管理器 → 模块 → 从文件安装），它的 `customize.sh` 以 `u:r:ksu:s0` 运行并执行 `setenforce 0`。

---

## 4. 设备上的环境约束（踩坑总结）

| 约束 | 表现 | 应对 |
|---|---|---|
| 三星 DEFEX | uid=0 从 `/data/adb`、`/data/local/tmp` exec 会被 SIGKILL(137)，日志 `[DEFEX] Safeplace violation` | 先 `echo u:r:ksu:s0 > /proc/self/attr/current` 再 exec |
| DEFEX 文件视图 | root shell 里 `/apex` 挂载被隐藏，`app_process` 报 `libnativeloader.so not found` | `nsenter -t 1 -m -- <cmd>` 进 init 的 mount namespace |
| SELinux | KSU 加载后自动 Enforcing | roothelper 模块 + `setenforce 0` |
| 每次开机 KASLR 变 | 旧 `kernelsu-abs.ko` 直接崩 | **必须重新 prelink** |
| exploit 竞态 | 每个 boot 只有一次机会 | 失败就重启，`root-loop-wifi2.sh` 会自动轮换 delay |
| USB / 无线 adb | 无线端口每次重启都变；USB 更稳 | `nmap -p 30000-65535` 扫端口，或直接用 USB |

---

## 5. 已知未解决问题

**Zygisk / LSPosed 在这台机器上无法注入**：

- Zygisk Next 1.5.2：zygote 里有 6 段 zygisk 映射，但 70 个运行进程 **0 个被注入**；`znctl dump-zn` 显示 `Modules: 0 / Injected Processes: 0`。
- Zygisk Next 1.3.4：连 zygote 映射都是 0，dmesg 无任何 `zn-daemon64` 日志。
- 判断：**machikado ptrace 抢占 zygote 的路径被三星 DEFEX/KDP/RKP 挡死**，与版本无关。
- 后续可选：KernelSU Next（内核态 Zygisk）、Frida（root + ptrace 附加 App）、或放弃注入方案。

详见 `notes/2026-10-28.md`。

---

## 6. 免责声明

仅供本人设备的研究与学习。临时 root 不稳定，任何一步都可能导致整机重启；不要在含敏感数据的设备上直接照搬。
