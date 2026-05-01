#!/usr/bin/env bash
# Temporary AF_ALG AEAD guard for Copy Fail / CVE-2026-31431.
#
# This installs a small BPF LSM program that denies AF_ALG bind() calls with
# salg_type == "aead". It is a mitigation, not a kernel fix. Replace it with
# vendor kernel errata, vendor livepatch, or a real kpatch when available.

set -euo pipefail

SERVICE_NAME="copyfail-bpf-guard"
INSTALL_DIR="/opt/${SERVICE_NAME}"
BPF_DIR="/sys/fs/bpf/${SERVICE_NAME}"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
SRC_PATH="${INSTALL_DIR}/block_afalg_aead.bpf.c"
OBJ_PATH="${INSTALL_DIR}/block_afalg_aead.bpf.o"
PIN_PATH="${BPF_DIR}/block_afalg_aead"

# SHA256 of the decoded embedded object. Regenerate the object from the C source below when changing the BPF program.
EMBEDDED_BPF_OBJECT_SHA256='6bbb899abb1e5a370de1b6e4109dcdd7d34e78aa119471071c362f96b66929fa'
EMBEDDED_BPF_OBJECT_B64='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AAADAHgBAAAAAAAAAAAAAAAAAAAAAAAAAwAFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwALAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwASAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAWAAAAAAAAAAAAAAAAAAAAAADLAAAAEgADAAAAAAAAAAAAmAEAAAAAAAD1AAAAEQAEAAAAAAAAAAAABAAAAAAAAAAIAAAAAAAAAAMAAAAJAAAAEQAAAAAAAAADAAAACgAAABUAAAAAAAAAAwAAAA4AAAAfAAAAAAAAAAMAAAAMAAAAIwAAAAAAAAADAAAACAAAAAgAAAAAAAAAAwAAAAsAAAAMAAAAAAAAAAMAAAALAAAAEAAAAAAAAAADAAAACwAAABQAAAAAAAAAAwAAAAsAAAAYAAAAAAAAAAMAAAALAAAAHAAAAAAAAAADAAAACwAAACAAAAAAAAAAAwAAAAsAAAAkAAAAAAAAAAMAAAALAAAAKAAAAAAAAAADAAAACwAAACwAAAAAAAAAAwAAAAsAAAAwAAAAAAAAAAMAAAALAAAANAAAAAAAAAADAAAACwAAADgAAAAAAAAAAwAAAAsAAAA8AAAAAAAAAAMAAAALAAAAQAAAAAAAAAADAAAACwAAAEQAAAAAAAAAAwAAAAsAAABIAAAAAAAAAAMAAAALAAAATAAAAAAAAAADAAAACwAAAFAAAAAAAAAAAwAAAAsAAABUAAAAAAAAAAMAAAALAAAAWAAAAAAAAAADAAAACwAAAFwAAAAAAAAAAwAAAAsAAABgAAAAAAAAAAMAAAALAAAAZAAAAAAAAAADAAAACwAAAGgAAAAAAAAAAwAAAAsAAABsAAAAAAAAAAMAAAALAAAAcAAAAAAAAAADAAAACwAAAHQAAAAAAAAAAwAAAAsAAAB4AAAAAAAAAAMAAAALAAAAfAAAAAAAAAADAAAACwAAAIAAAAAAAAAAAwAAAAsAAAAIAAAAAAAAAAIAAAARAAAAEAAAAAAAAAACAAAAAgAAAMgAAAAAAAAABAAAABEAAAAsAAAAAAAAAAQAAAACAAAA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'

log() { printf '==> %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Temporary AF_ALG AEAD guard for Copy Fail / CVE-2026-31431.

Usage:
  copyfail-bpf-guard.sh check
  sudo copyfail-bpf-guard.sh install-deps
  sudo copyfail-bpf-guard.sh install
  copyfail-bpf-guard.sh status
  copyfail-bpf-guard.sh probe
  sudo copyfail-bpf-guard.sh disable
  sudo copyfail-bpf-guard.sh uninstall
  sudo copyfail-bpf-guard.sh install-build-deps
  sudo copyfail-bpf-guard.sh rebuild

This is a mitigation, not a kernel fix.
EOF
}

need_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        die "this command must run as root; retry with sudo"
    fi
}

have() {
    command -v "$1" >/dev/null 2>&1
}

find_cmd() {
    local name="$1"
    local candidate

    if command -v "${name}" >/dev/null 2>&1; then
        command -v "${name}"
        return 0
    fi

    for candidate in "/usr/sbin/${name}" "/sbin/${name}" "/usr/bin/${name}" "/bin/${name}"; do
        if [[ -x "${candidate}" ]]; then
            printf '%s\n' "${candidate}"
            return 0
        fi
    done

    return 1
}

bpftool_bin() {
    find_cmd bpftool 2>/dev/null || true
}

bpftool_feature_probe() {
    local bpf_tool="$1"

    if [[ "${EUID}" -eq 0 ]]; then
        "${bpf_tool}" feature probe kernel 2>/dev/null || true
    elif have sudo && sudo -n true 2>/dev/null; then
        sudo -n "${bpf_tool}" feature probe kernel 2>/dev/null || true
    else
        "${bpf_tool}" feature probe kernel 2>/dev/null || true
    fi
}

systemd_available() {
    have systemctl && [[ -d /run/systemd/system ]]
}

ensure_bpffs() {
    [[ -d /sys/fs/bpf ]] || mkdir -p /sys/fs/bpf
    if ! awk '$2 == "/sys/fs/bpf" && $3 == "bpf" { found = 1 } END { exit !found }' /proc/mounts; then
        log "mounting bpffs at /sys/fs/bpf"
        mount -t bpf bpf /sys/fs/bpf
    fi
}

kernel_config_value() {
    local key="$1"
    local config="/boot/config-$(uname -r)"

    if [[ -r "${config}" ]]; then
        grep -E "^${key}=" "${config}" | tail -1 || true
        return
    fi

    if [[ -r /proc/config.gz ]] && have zcat; then
        zcat /proc/config.gz | grep -E "^${key}=" | tail -1 || true
    fi
}

check_support() {
    local rc=0
    local bpf_tool
    bpf_tool="$(bpftool_bin)"

    log "host: $(hostname -f 2>/dev/null || hostname)"
    log "kernel: $(uname -r)"

    if [[ -n "${bpf_tool}" ]]; then
        log "bpftool: ${bpf_tool}"
    else
        warn "bpftool is missing"
        rc=1
    fi

    if have clang; then
        log "clang: $(command -v clang)"
    else
        warn "clang is missing; install can still use the embedded BPF object, but rebuild will be unavailable"
    fi

    local bpf_lsm_config
    bpf_lsm_config="$(kernel_config_value CONFIG_BPF_LSM || true)"
    if [[ "${bpf_lsm_config}" == "CONFIG_BPF_LSM=y" ]]; then
        log "CONFIG_BPF_LSM=y"
    else
        warn "CONFIG_BPF_LSM is not confirmed enabled (${bpf_lsm_config:-missing})"
    fi

    local bpf_syscall_config
    bpf_syscall_config="$(kernel_config_value CONFIG_BPF_SYSCALL || true)"
    if [[ "${bpf_syscall_config}" == "CONFIG_BPF_SYSCALL=y" ]]; then
        log "CONFIG_BPF_SYSCALL=y"
    else
        warn "CONFIG_BPF_SYSCALL is not confirmed enabled (${bpf_syscall_config:-missing})"
    fi

    if [[ -r /sys/kernel/security/lsm ]]; then
        local lsms
        lsms="$(cat /sys/kernel/security/lsm)"
        log "active LSMs: ${lsms}"
        if [[ ",${lsms}," != *",bpf,"* ]]; then
            warn "BPF LSM is not active; this usually requires boot-time LSM configuration"
            rc=1
        fi
    else
        warn "/sys/kernel/security/lsm is not readable; cannot confirm active BPF LSM"
        rc=1
    fi

    if [[ -n "${bpf_tool}" ]]; then
        local feature_out
        feature_out="$(bpftool_feature_probe "${bpf_tool}")"
        if grep -q 'program_type lsm is available' <<<"${feature_out}"; then
            log "BPF LSM program type is available"
        else
            warn "bpftool does not report BPF LSM program support"
            rc=1
        fi
    fi

    if systemd_available; then
        log "systemd: available for persistence"
    else
        warn "systemd is not available; install will load the guard for this boot only"
    fi

    return "${rc}"
}

install_deps() {
    need_root
    install_packages bpftool
}

install_build_deps() {
    need_root
    install_packages bpftool clang llvm
}

install_packages() {
    if have dnf; then
        dnf install -y "$@"
    elif have yum; then
        yum install -y "$@"
    elif have apt-get; then
        apt-get update
        apt-get install -y "$@"
    elif have zypper; then
        zypper --non-interactive install "$@"
    elif have pacman; then
        pacman -Sy --noconfirm "$@"
    elif have apk; then
        apk add "$@"
    else
        die "unsupported package manager; install missing packages manually: $*"
    fi
}

write_source() {
    install -d -m 0755 "${INSTALL_DIR}"
    cat > "${SRC_PATH}" <<'BPF_EOF'
#define SEC(name) __attribute__((section(name), used))
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define AF_ALG 38
#define EACCES 13

struct sockaddr_alg_min {
    __u16 salg_family;
    __u8 salg_type[14];
    __u32 salg_feat;
    __u32 salg_mask;
    __u8 salg_name[64];
};

static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)113;

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/socket_bind")
int block_afalg_aead(__u64 *ctx)
{
    void *addr = (void *)ctx[1];
    int addrlen = (int)ctx[2];
    int ret = (int)ctx[3];
    struct sockaddr_alg_min alg = {};

    if (ret != 0)
        return ret;

    if (addrlen < 16)
        return 0;

    if (bpf_probe_read_kernel(&alg, sizeof(alg), addr) != 0)
        return 0;

    if (alg.salg_family != AF_ALG)
        return 0;

    if (alg.salg_type[0] == 'a' && alg.salg_type[1] == 'e' &&
        alg.salg_type[2] == 'a' && alg.salg_type[3] == 'd' &&
        alg.salg_type[4] == 0)
        return -EACCES;

    return 0;
}
BPF_EOF
    chmod 0644 "${SRC_PATH}"
}

build_object() {
    have clang || die "clang is missing; run '${0} install-build-deps' or install clang/llvm manually"
    write_source
    log "building BPF object"
    clang -O2 -g -target bpf -c "${SRC_PATH}" -o "${OBJ_PATH}"
    chmod 0644 "${OBJ_PATH}"
}

write_embedded_object() {
    have base64 || die "base64 is missing"
    have sha256sum || die "sha256sum is missing"
    write_source
    log "installing embedded BPF object"
    printf '%s' "${EMBEDDED_BPF_OBJECT_B64}" | base64 -d > "${OBJ_PATH}"
    local actual_sha
    actual_sha="$(sha256sum "${OBJ_PATH}" | awk '{print $1}')"
    [[ "${actual_sha}" == "${EMBEDDED_BPF_OBJECT_SHA256}" ]] || die "embedded BPF object checksum mismatch"
    chmod 0644 "${OBJ_PATH}"
}

detach_guard() {
    local bpf_tool
    bpf_tool="$(bpftool_bin)"
    [[ -n "${bpf_tool}" ]] || return 0

    "${bpf_tool}" link detach pinned "${PIN_PATH}" >/dev/null 2>&1 || true
    rm -rf "${BPF_DIR}"
}

load_guard() {
    need_root
    local bpf_tool
    bpf_tool="$(bpftool_bin)"
    [[ -n "${bpf_tool}" ]] || die "bpftool is missing; run install-deps first"
    [[ -r "${OBJ_PATH}" ]] || die "BPF object not found at ${OBJ_PATH}; run install first"

    ensure_bpffs
    detach_guard
    mkdir -p "${BPF_DIR}"

    log "loading BPF LSM guard"
    "${bpf_tool}" prog loadall "${OBJ_PATH}" "${BPF_DIR}" autoattach
}

write_unit() {
    local bpf_tool
    bpf_tool="$(bpftool_bin)"
    [[ -n "${bpf_tool}" ]] || die "bpftool is missing"

    cat > "${UNIT_PATH}" <<EOF
[Unit]
Description=Temporary AF_ALG AEAD guard for Copy Fail / CVE-2026-31431
Documentation=https://copy.fail/
After=sys-fs-bpf.mount
ConditionPathExists=/sys/fs/bpf

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/sh -c '${bpf_tool} link detach pinned ${PIN_PATH} >/dev/null 2>&1 || true'
ExecStartPre=/bin/rm -rf ${BPF_DIR}
ExecStartPre=/bin/mkdir -p ${BPF_DIR}
ExecStart=${bpf_tool} prog loadall ${OBJ_PATH} ${BPF_DIR} autoattach
ExecStop=/bin/sh -c '${bpf_tool} link detach pinned ${PIN_PATH} >/dev/null 2>&1 || true'
ExecStopPost=/bin/rm -rf ${BPF_DIR}

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "${UNIT_PATH}"
}

install_guard() {
    need_root
    check_support || die "host does not appear ready for this BPF LSM guard; see warnings above"
    write_embedded_object

    if systemd_available; then
        write_unit
        systemctl daemon-reload
        systemctl enable --now "${SERVICE_NAME}.service"
    else
        load_guard
        warn "loaded guard for current boot only because systemd is unavailable"
    fi

    probe || true
}

disable_guard() {
    need_root

    if systemd_available && [[ -f "${UNIT_PATH}" ]]; then
        systemctl disable --now "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
    fi

    detach_guard
    log "guard disabled"
}

uninstall_guard() {
    need_root
    disable_guard
    rm -f "${UNIT_PATH}"
    rm -rf "${INSTALL_DIR}"
    if systemd_available; then
        systemctl daemon-reload
    fi
    log "guard uninstalled"
}

status_guard() {
    local bpf_tool
    bpf_tool="$(bpftool_bin)"

    if systemd_available && [[ -f "${UNIT_PATH}" ]]; then
        systemctl --no-pager --full status "${SERVICE_NAME}.service" || true
    else
        log "systemd unit: not installed"
    fi

    if [[ -n "${bpf_tool}" && -e "${PIN_PATH}" ]]; then
        log "pinned BPF link: ${PIN_PATH}"
        "${bpf_tool}" link show pinned "${PIN_PATH}" || true
    else
        warn "pinned BPF link not found at ${PIN_PATH}"
    fi
}

probe() {
    if ! have python3; then
        warn "python3 is missing; skipping socket probe"
        return 0
    fi

    python3 - <<'PY_EOF'
import socket

checks = [
    ("inet/tcp", lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)),
    ("afalg/create-only", lambda: socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)),
    ("alg/hash-sha256", lambda: (lambda s: (s.bind(("hash", "sha256")), s)[1])(socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0))),
    ("alg/skcipher-cbc-aes", lambda: (lambda s: (s.bind(("skcipher", "cbc(aes)")), s)[1])(socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0))),
    ("alg/aead-gcm-aes", lambda: (lambda s: (s.bind(("aead", "gcm(aes)")), s)[1])(socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0))),
    ("alg/aead-authencesn", lambda: (lambda s: (s.bind(("aead", "authencesn(hmac(sha256),cbc(aes))")), s)[1])(socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0))),
]

for name, fn in checks:
    try:
        s = fn()
    except Exception as exc:
        print(f"{name}: blocked-or-failed: {type(exc).__name__}: {exc}")
    else:
        print(f"{name}: available")
        s.close()
PY_EOF
}

cmd="${1:-help}"
case "${cmd}" in
    check)
        check_support
        ;;
    install-deps)
        install_deps
        ;;
    install-build-deps)
        install_build_deps
        ;;
    rebuild)
        need_root
        build_object
        ;;
    install|enable)
        install_guard
        ;;
    load)
        load_guard
        ;;
    disable)
        disable_guard
        ;;
    uninstall|remove)
        uninstall_guard
        ;;
    status)
        status_guard
        ;;
    probe)
        probe
        ;;
    help|-h|--help)
        usage
        ;;
    *)
        usage
        exit 1
        ;;
esac
