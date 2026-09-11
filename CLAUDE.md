# FastROS — instructions for Claude

FastROS is a container-native OS written in Rust from scratch (no_std kernel, x86_64).
Goal: a precise, fast, clean, architecturally sound OS with Docker + Kubernetes
functionality built in (`fastman`), and security (memory, OS, firewall, network)
stronger than Linux.

UI/explanations to the owner: **Uzbek**. Code, identifiers, commits: **English**.

---

## 🚨 RULE #1 — NEVER TOUCH THE HOST

This repo lives on a production VPS. **Every action must have zero effect on the
host machine.** Everything QEMU-related — building the kernel, booting it, SSH
testing — runs **only inside Docker containers**.

- Build: `docker compose build` (or `docker build ...`). Never `cargo build` on the host.
- Boot: `docker compose up -d` — QEMU runs inside the `fastros` container.
- Test over SSH **from inside a container** (the runtime image has `ssh` + `sshpass`):
  `docker exec fastros-fastros-1 sshpass -p root ssh -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null -p 22 root@127.0.0.1 '<cmd>'`
- Never `apt install` anything on the host, never edit `/etc`, ufw, sshd, systemd.
- Never install Rust, NASM, QEMU, sshpass, expect etc. on the host.
- The only host state FastROS may own is `./disk/data.img` (guest persistent disk)
  and the source tree itself. Scratch files go in the session scratchpad, not in the repo.
- Host-side `docker image prune -a` / `system prune` are forbidden (other services
  on this box depend on their images).

## Build / run / test

```sh
docker compose up -d --build          # build kernel inside Docker + boot in QEMU
docker compose logs -f                # serial console
docker run --rm fastros test          # boot smoke test (SSH login round trip)
```

Guest: e1000 on QEMU user-net, 10.0.2.15/24, gw 10.0.2.2, DNS 10.0.2.3.
Guest SSH :22 → container :22 → host `${FASTROS_BIND}:${FASTROS_PORT}` (see `.env`).
No KVM on this VPS → TCG.

## Git

Remote `origin` = `github.com/abduraimovabdurahmon/fastros`, branch `master`.
Push with plain `git push origin master` (local credential.helper points at
`/volumes/configs/github/git-credentials`). Commit freely; keep commits focused.

## Code rules

- Precision over "it probably works": every command must be verified over SSH.
- Strict typing, small reusable modules, clean layering (see `docs/ARCHITECTURE.md`).
- Output formatting of every shell command must be exact (column alignment, CRLF
  handling over SSH, no stray escape codes).
