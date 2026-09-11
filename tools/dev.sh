#!/usr/bin/env bash
# FastROS development loop — everything runs inside the fastros-dev container;
# the host only needs Docker. Build output lives in Docker volumes.
#
#   tools/dev.sh image          build the fastros-dev image
#   tools/dev.sh build          build the kernel (release)
#   tools/dev.sh unit           host unit tests of lib/*
#   tools/dev.sh boot [secs]    boot in QEMU, print the serial log, stop
#   tools/dev.sh up             boot in the background (container fastros-dev-vm)
#   tools/dev.sh ssh 'cmd'      run a command in the guest over SSH
#   tools/dev.sh test [args]    integration tests (pytest over SSH)
#   tools/dev.sh down           stop the background VM
#   tools/dev.sh sh             shell in the dev container
set -eu
cd "$(dirname "$0")/.."
IMG=fastros-dev
# Parallel checkouts (git worktrees) set these to get their own VM and build dir.
VM=${FASTROS_VM:-fastros-dev-vm}
NET=${FASTROS_NET:-fastros-dev-net}
TARGET=${FASTROS_TARGET_VOL:-fastros-target}
# Dev containers yield the CPU to production services on the same host.
PRIO="--cpu-shares 256"
VOLS="$PRIO -v $PWD:/src -v $TARGET:/src/target -v fastros-cargo:/usr/local/cargo/registry"
KERNEL=/src/target/x86_64-unknown-none/release/fastros

run() { docker run --rm $VOLS "$@"; }

ensure_net() { docker network inspect $NET >/dev/null 2>&1 || docker network create $NET >/dev/null; }

case ${1:-} in
image)
    ctx=$(mktemp -d)
    cp rust-toolchain.toml docker/dev.Dockerfile "$ctx/"
    docker build -q -f "$ctx/dev.Dockerfile" -t $IMG "$ctx"
    rm -rf "$ctx"
    ;;
build)
    run -w /src/kernel $IMG cargo build --release "${@:2}"
    ;;
unit)
    run $IMG cargo test --workspace --exclude fastros-kernel "${@:2}"
    ;;
boot)
    secs=${2:-15}
    run $IMG sh -c "timeout $secs qemu-system-x86_64 -machine pc -cpu max -m 512M -kernel $KERNEL \
        -display none -monitor none -serial stdio -no-reboot -append 'panic=poweroff' || true"
    ;;
up)
    ensure_net
    docker rm -f $VM >/dev/null 2>&1 || true
    docker run -d --name $VM --network $NET $VOLS -e FASTROS_KERNEL=$KERNEL \
        -e FASTROS_DISK=/tmp/data.img -e FASTROS_MEM=${FASTROS_MEM:-512M} \
        --entrypoint sh $IMG /src/docker/entrypoint.sh run >/dev/null
    echo "started $VM (docker logs -f $VM)"
    ;;
down)
    docker rm -f $VM >/dev/null 2>&1 || true
    ;;
ssh)
    shift
    docker exec $VM sshpass -p root ssh -p 22 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR root@127.0.0.1 "$@"
    ;;
test)
    shift
    ensure_net
    docker run --rm --network $NET $VOLS -w /src/tests -e FASTROS_HOST=$VM $IMG python3 -m pytest -q "$@"
    ;;
sh)
    shift
    docker run --rm -it $VOLS $IMG sh "$@"
    ;;
*)
    sed -n '2,14p' "$0"
    exit 2
    ;;
esac
