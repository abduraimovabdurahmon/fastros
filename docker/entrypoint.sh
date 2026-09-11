#!/bin/sh
# Boot the FastROS kernel in QEMU inside the container.
#
# The guest gets an e1000 NIC on QEMU user networking (10.0.2.15, gateway
# 10.0.2.2) and its SSH server (guest port 22) is forwarded to container
# port 22 — publish that one to reach the shell. Serial goes to stdout, so
# `docker logs` shows the boot log.
#
# Modes (first argument):
#   run    boot and keep running                                  [default]
#   test   boot, log in over SSH, check the answer, exit 0/1
#   shell  /bin/sh inside the container
# In run/test mode, anything after the mode is passed to QEMU verbatim.
#
# Environment:
#   FASTROS_KERNEL   kernel ELF to boot            (default: the one baked into the image)
#   FASTROS_DISK     persistent disk image, created (64 MB) if missing
#                    (default: /var/lib/fastros/data.img — mount a folder there)
#   FASTROS_MEM      guest RAM                     (default: 256M)
#   FASTROS_ACCEL    auto | kvm | tcg              (default: auto — KVM when usable)
#   FASTROS_TIMEOUT  seconds `test` may take       (default: 120)
#   QEMU_EXTRA_ARGS  extra QEMU flags, word-split

set -eu

mode=${1:-run}
[ $# -gt 0 ] && shift

if [ "$mode" = shell ]; then
    exec /bin/sh "$@"
fi

kernel=${FASTROS_KERNEL:-/opt/fastros/fastros}
if [ ! -f "$kernel" ]; then
    echo "fastros: kernel not found: $kernel" >&2
    exit 1
fi

disk=${FASTROS_DISK:-/var/lib/fastros/data.img}
if [ ! -f "$disk" ]; then
    # Blank disk: the kernel formats it on first boot (diskfs).
    mkdir -p "$(dirname "$disk")"
    truncate -s 64M "$disk"
    # Hand it to whoever owns the mounted folder, not to the container's root.
    chown "$(stat -c %u:%g "$(dirname "$disk")")" "$disk" 2>/dev/null || true
fi

# KVM only helps when the host itself is x86_64 and /dev/kvm was passed in
# (docker run --device /dev/kvm). Everywhere else — macOS, Windows, arm64 —
# QEMU uses TCG software emulation.
kvm_usable() {
    [ "$(uname -m)" = x86_64 ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]
}
case ${FASTROS_ACCEL:-auto} in
    auto) if kvm_usable; then accel=kvm; else accel=tcg; fi ;;
    kvm)  kvm_usable || { echo "fastros: FASTROS_ACCEL=kvm but /dev/kvm is not usable" >&2; exit 1; }
          accel=kvm ;;
    tcg)  accel=tcg ;;
    *)    echo "fastros: FASTROS_ACCEL must be auto, kvm or tcg" >&2; exit 1 ;;
esac

# `-machine pc` (i440FX/PIIX4) is load-bearing: the shell's `exit` command
# powers off through the PIIX4 ACPI port 0x604, which q35 does not have.
# The disk must be IDE index 0 (primary master) — the only drive the ATA
# driver probes (drivers/block/ata: select 0xA0).
set -- -machine pc -accel "$accel" -m "${FASTROS_MEM:-256M}" -kernel "$kernel" \
       -display none -monitor none -serial stdio \
       -netdev user,id=net0,hostfwd=tcp::22-:22 -device e1000,netdev=net0 \
       -drive "file=$disk,format=raw,if=ide,index=0" \
       "$@"
[ "$accel" = kvm ] && set -- -cpu host "$@"
# shellcheck disable=SC2086
[ -n "${QEMU_EXTRA_ARGS:-}" ] && set -- "$@" $QEMU_EXTRA_ARGS

echo "fastros: accel=$accel mem=${FASTROS_MEM:-256M} disk=$disk" >&2

case $mode in
    run)
        echo "fastros: SSH on container port 22 (user root, password root)" >&2
        exec qemu-system-x86_64 "$@"
        ;;
    test)
        log=$(mktemp)
        qemu-system-x86_64 "$@" > "$log" 2>&1 &
        qemu=$!
        deadline=$(( $(date +%s) + ${FASTROS_TIMEOUT:-120} ))
        result=timeout
        while [ "$(date +%s)" -lt "$deadline" ]; do
            if grep -q 'KERNEL PANIC' "$log"; then result=panic; break; fi
            kill -0 "$qemu" 2>/dev/null || { result=exited; break; }
            if grep -q 'Boot complete' "$log"; then
                # Full round trip: key exchange, password auth, exec channel.
                if out=$(sshpass -p root ssh -p 22 -o StrictHostKeyChecking=no \
                           -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
                           -o ConnectTimeout=10 root@127.0.0.1 fastros-test 2>&1); then
                    case $out in *fastros-test*) result=pass; break ;; esac
                fi
            fi
            sleep 2
        done
        kill "$qemu" 2>/dev/null || true
        wait "$qemu" 2>/dev/null || true
        cat "$log"
        echo
        [ -n "${out:-}" ] && echo "ssh: $out"
        echo "fastros: test $result" >&2
        [ "$result" = pass ]
        ;;
    *)
        echo "fastros: unknown mode '$mode' (run|test|shell)" >&2
        exit 2
        ;;
esac
