# copyfail-bpf-guard

Temporary no-reboot mitigation for Copy Fail / CVE-2026-31431.

**Why this exists.** The goal was to reduce exposure without scheduling disruptive
reboots across many hosts *or* building and maintaining livepatch / kpatch
modules for each exact kernel revision in the fleet. A small BPF LSM guard can
be deployed quickly and rolled back cleanly; it is an **interim control** until
official vendor kernels, vendor livepatches, or other supported fixes are
available for your platforms.

This project installs a BPF LSM program that denies `AF_ALG` binds where
`salg_type == "aead"`. That blocks the known vulnerable AEAD AF_ALG interface
while leaving normal sockets and non-AEAD AF_ALG uses available.

**This is not a kernel fix.** It does not patch vulnerable code in the kernel;
it adds a policy layer that refuses the risky bind. Replace it with vendor
kernel errata, vendor livepatch, or a maintained kpatch for your exact running
kernel as soon as that is practical.

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

**Environment (must all be true for this tool to help)**

- Linux hosts only — not applicable on non-Linux systems.
- BPF LSM **enabled in the kernel config and active** at runtime (`bpf` in the
  active LSM list). If BPF LSM is unavailable or inactive, this guard cannot
  attach; use vendor fixes or another mitigation path instead.
- `bpftool`, `clang`, and `llvm` available (build and load the program).
- `systemd` for reboot persistence (service unit under `/etc/systemd`).

**Where it is likely to apply**  
Tested and expected to work on modern enterprise-style kernels (for example
RHEL / Rocky 9–class 5.14+ builds with BPF LSM on) and on other current
distributions that ship BPF LSM and keep it enabled — always confirm with the
checks below on each image.

**Where it does *not* apply or adds no value**

- BPF LSM missing, disabled, or not in the active LSM stack.
- Environments where vulnerable `AF_ALG` AEAD is already absent, disabled, or
  blocked by other means — nothing further to gain here.
- Scenarios where you need protection **from fully privileged administrators**
  who can unload BPF, stop services, or load arbitrary kernel code — this
  mitigation is not a boundary against root on the host.

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

This guard is designed for **emergency, short-lived** reduction of exposure when
mass reboots or per-kernel livepatch/kpatch work are not the first lever you
want to pull. It does not modify vulnerable kernel code; it is **not** a
substitute for an official kernel fix, livepatch, or kpatch aligned to your
build.

It only helps on Linux with BPF LSM actually available and active, and only
addresses the AEAD `AF_ALG` bind surface this program targets — not every class
of kernel bug.

Privileged users who can unload BPF programs, stop system services, or load
their own kernel code can remove or bypass this mitigation. Treat it as a
defense for ordinary local users and untrusted workloads, not as protection
from host administrators.
