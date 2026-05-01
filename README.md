# copyfail-bpf-guard

Temporary no-reboot mitigation for Copy Fail / CVE-2026-31431.

This project installs a small BPF LSM program that denies `AF_ALG` binds where
`salg_type == "aead"`. That blocks the known vulnerable AEAD AF_ALG interface
while leaving normal sockets and non-AEAD AF_ALG uses available.

This is a mitigation, not a kernel fix. Replace it with vendor kernel errata,
vendor livepatch, or a real kpatch as soon as one is available for your exact
running kernel.

## Quick Start

```bash
git clone https://github.com/pizzasuprema/copyfail-bpf-guard.git
cd copyfail-bpf-guard

./copyfail-bpf-guard.sh check
sudo ./copyfail-bpf-guard.sh install-deps
sudo ./copyfail-bpf-guard.sh install
./copyfail-bpf-guard.sh probe
```

Expected protected probe output:

```text
inet/tcp: available
afalg/create-only: available
alg/hash-sha256: available
alg/skcipher-cbc-aes: available
alg/aead-gcm-aes: blocked-or-failed: PermissionError: [Errno 13] Permission denied
alg/aead-authencesn: blocked-or-failed: PermissionError: [Errno 13] Permission denied
```

## Requirements

- A Linux kernel with BPF LSM enabled and active.
- `bpftool`, `clang`, and `llvm` to build and load the guard.
- `systemd` for reboot persistence.

The installer supports common package managers: `dnf`, `yum`, `apt-get`,
`zypper`, `pacman`, and `apk`.

Check support:

```bash
./copyfail-bpf-guard.sh check
```

Useful manual checks:

```bash
grep '^CONFIG_BPF_LSM=' /boot/config-$(uname -r)
cat /sys/kernel/security/lsm
sudo bpftool feature probe kernel | grep 'program_type lsm'
```

You want `CONFIG_BPF_LSM=y`, `bpf` in the active LSM list, and
`eBPF program_type lsm is available`.

## Commands

```bash
./copyfail-bpf-guard.sh check              # read-only support check
sudo ./copyfail-bpf-guard.sh install-deps  # install bpftool, clang, llvm
sudo ./copyfail-bpf-guard.sh install       # build, load, and persist guard
./copyfail-bpf-guard.sh status             # show systemd/BPF status
./copyfail-bpf-guard.sh probe              # test socket behavior
sudo ./copyfail-bpf-guard.sh disable       # stop guard, keep files
sudo ./copyfail-bpf-guard.sh uninstall     # stop guard and remove files
```

## What It Blocks

The guard attaches to the LSM `socket_bind` hook. It reads the supplied
`sockaddr_alg` and denies only this case:

```text
salg_family == AF_ALG
salg_type   == "aead"
```

It intentionally does not block:

- Normal TCP/UDP/Unix sockets.
- `AF_ALG` socket creation by itself.
- `AF_ALG` `hash` binds.
- `AF_ALG` `skcipher` binds.

## Files Installed

```text
/opt/copyfail-bpf-guard/block_afalg_aead.bpf.c
/opt/copyfail-bpf-guard/block_afalg_aead.bpf.o
/etc/systemd/system/copyfail-bpf-guard.service
/sys/fs/bpf/copyfail-bpf-guard/block_afalg_aead
```

## Rollback

```bash
sudo ./copyfail-bpf-guard.sh disable
```

Full removal:

```bash
sudo ./copyfail-bpf-guard.sh uninstall
```

## Notes

This guard is designed for emergency reduction of exposure. It does not modify
the vulnerable kernel code and it is not a substitute for patched kernels.

Privileged users who can unload BPF programs, stop system services, or load
their own kernel code can remove or bypass this mitigation. Treat it as a
defense for ordinary local users and untrusted workloads, not as protection
from host administrators.
