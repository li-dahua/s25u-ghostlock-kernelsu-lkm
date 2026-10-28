# 编译说明

本目录不包含产物（`.ko` 通常 4–5 MB，且每次开机需重新 prelink），只记录复现方式。

## 环境

- 主机：Ubuntu 22.04 x86_64（本机为 ray-DR521，Xeon E5-2666 v3 / 32G）
- NDK：android-ndk-r27c（`/home/ray/android-ndk-r27c`）
- 内核源码：AOSP `android15-6.6` 分支，checkout 到设备同版本 `6.6.98`
  - 需要设备原生 `.config`（可从 `Image` 反推，或用 samsung kernel source 对应版本）
  - 编译出 `vmlinux` + `Module.symvers`（KSU 编译依赖 `Module.symvers`）

## KernelSU 模块

```bash
git clone https://github.com/tiann/KernelSU -b v3.2.5 /data/tools/KernelSU

cd /data/tools/KernelSU
make KDIR=/data/ksrc-6.6.98 \
     ARCH=arm64 LLVM=1 \
     KBUILD_MODPOST_WARN=1 \
     LOCALVERSION='-android15-8-pd6ff1cd-abogkiS9380ZHSDCZH1-4k' \
     CONFIG_KSU=m \
     CONFIG_KSU_SAMSUNG_KDP=y \
     CONFIG_KSU_SAMSUNG_RKP=y \
     CONFIG_KSU_SAMSUNG_DEFEX=y \
     CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT=y \
     -j20
```

产物：`/data/tools/KernelSU/kernelsu.ko`

### 几个关键选项

- `LOCALVERSION` 必须与设备 `uname -r` 后缀**逐字符一致**，否则 vermagic 校验失败。
- `CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT=y`：跳过内核对 text patch 的做法（三星 KDP 会拦截）。副作用：模块安装脚本里的 `check_sepolicy` 必然失败，安装 Zygisk Next 等模块时要 patch 掉该调用。
- KDP / RKP / DEFEX 三个 compat 开关必须开，否则加载即 panic 或被安全模块踢掉。

## 管理器

必须与内核模块版本对齐：**v3.2.5 / 32525**。管理器升级到 32680 会要求匹配的新内核接口，本方案不支持。
