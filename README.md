# copyfail-bpf-guard

No-reboot BPF LSM mitigation for Copy Fail / CVE-2026-31431.

Keywords: `CVE-2026-31431`, `Copy Fail`, `AF_ALG`, `algif_aead`, `BPF LSM`,
`eBPF`, `Linux kernel`, `local privilege escalation`, `no reboot`, `temporary
mitigation`.

## Why This Exists

Copy Fail is a Linux local privilege escalation that abuses the userspace crypto
API: `AF_ALG` + `algif_aead` + `splice()`. The real fix is a patched kernel,
vendor livepatch, or maintained kpatch for your exact kernel.

This project is an interim control for the awkward middle: you need to reduce
exposure now, but you do not want to reboot a fleet immediately or compile a
per-kernel livepatch for every running kernel revision. It installs a small BPF
LSM program that denies `AF_ALG` binds where `salg_type == "aead"`, blocking the
known vulnerable AEAD interface while leaving normal sockets and non-AEAD
`AF_ALG` uses available.

## Quick Start

```bash
git clone https://github.com/pizzasuprema/copyfail-bpf-guard.git
cd copyfail-bpf-guard

./copyfail-bpf-guard.sh check
sudo ./copyfail-bpf-guard.sh install-deps
sudo ./copyfail-bpf-guard.sh install
./copyfail-bpf-guard.sh probe
```

The default install uses an embedded, checksum-verified BPF object. Target hosts
need `bpftool`; `clang` and `llvm` are only needed if you want to rebuild the
BPF object from source.

## Demo Output

Before the guard, AEAD binds are usually available:

```text
alg/aead-gcm-aes: available
alg/aead-authencesn: available
```

After install, normal sockets and non-AEAD `AF_ALG` continue to work, but AEAD
binds are denied:

```text
inet/tcp: available
afalg/create-only: available
alg/hash-sha256: available
alg/skcipher-cbc-aes: available
alg/aead-gcm-aes: blocked-or-failed: PermissionError: [Errno 13] Permission denied
alg/aead-authencesn: blocked-or-failed: PermissionError: [Errno 13] Permission denied
```

## Requirements

This is for Linux hosts with BPF LSM enabled in the kernel config and active at
runtime. You should see `CONFIG_BPF_LSM=y`, `bpf` in the active LSM list, and
`eBPF program_type lsm is available`.

```bash
grep '^CONFIG_BPF_LSM=' /boot/config-$(uname -r)
cat /sys/kernel/security/lsm
sudo bpftool feature probe kernel | grep 'program_type lsm'
```

Tested and expected to work on modern enterprise-style kernels such as RHEL /
Rocky 9-class 5.14+ builds with BPF LSM active, and on other current Linux
distributions that ship BPF LSM and keep it enabled. Always run `check` on each
image before rollout.

This does not help on non-Linux systems, kernels without active BPF LSM, or
systems where the vulnerable AEAD `AF_ALG` path is already absent, patched, or
blocked by other means.

## How It Compares

| Approach | No reboot | Works when `algif_aead` is built in | Persistent | Scope |
| --- | --- | --- | --- | --- |
| Vendor kernel update | No | Yes | Yes | Real fix |
| Vendor livepatch / kpatch | Yes | Yes | Yes | Real or near-real fix |
| Module unload / blacklist | Sometimes | No | Usually | Blocks module load |
| Kernel arg / initcall blacklist | No | Yes | Yes | Blocks init at boot |
| Kubernetes DaemonSet BPF blocker | Yes | Yes | While pod runs | Cluster nodes |
| `copyfail-bpf-guard` | Yes | Yes | Yes with systemd | Host-level BPF LSM guard |

This guard is more precise than broad `AF_ALG` blockers because it attaches to
`socket_bind` and denies only this case:

```text
salg_family == AF_ALG
salg_type   == "aead"
```

It intentionally does not block normal TCP/UDP/Unix sockets, `AF_ALG` socket
creation by itself, `AF_ALG` `hash` binds, or `AF_ALG` `skcipher` binds.

## Commands

```bash
./copyfail-bpf-guard.sh check                    # read-only support check
sudo ./copyfail-bpf-guard.sh install-deps        # install bpftool
sudo ./copyfail-bpf-guard.sh install             # load and persist guard
./copyfail-bpf-guard.sh status                   # show systemd/BPF status
./copyfail-bpf-guard.sh probe                    # test socket behavior
sudo ./copyfail-bpf-guard.sh disable             # stop guard, keep files
sudo ./copyfail-bpf-guard.sh uninstall           # stop guard and remove files
sudo ./copyfail-bpf-guard.sh install-build-deps  # install bpftool, clang, llvm
sudo ./copyfail-bpf-guard.sh rebuild             # rebuild object from source
```

The installer supports common package managers: `dnf`, `yum`, `apt-get`,
`zypper`, `pacman`, and `apk`.

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

## Repository Topics

Suggested GitHub topics:

```text
cve-2026-31431
copy-fail
linux-kernel
ebpf
bpf-lsm
af-alg
algif-aead
security
mitigation
linux
```

Suggested repository description:

```text
No-reboot BPF LSM mitigation for Copy Fail / CVE-2026-31431
```

## Limitations

This is a mitigation, not a kernel fix. It does not patch vulnerable code in the
kernel; it adds a policy layer that refuses the risky bind. Replace it with
vendor kernel errata, vendor livepatch, or a maintained kpatch for your exact
running kernel as soon as that is practical.

Privileged users who can unload BPF programs, stop system services, or load
their own kernel code can remove or bypass this mitigation. Treat it as a
defense for ordinary local users and untrusted workloads, not as protection from
host administrators.
