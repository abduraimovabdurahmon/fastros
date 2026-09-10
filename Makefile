TARGET := x86_64-unknown-none
BIN    := target/$(TARGET)/debug/fastros
QEMU   := "C:/Program Files/QEMU/qemu-system-x86_64.exe"
DISK   := disk/data.img

# Network: QEMU user-mode networking with e1000 NIC.
# Guest IP: 10.0.2.15  Gateway: 10.0.2.2  DNS: 10.0.2.3
# Port forward: host:2222 → guest:22 (SSH)
NET    := -netdev user,id=net0,hostfwd=tcp::2222-:22 -device e1000,netdev=net0

# Persistent storage: 64 MB raw disk image (IDE secondary)
DRIVE  := -drive file=$(DISK),format=raw,if=ide,index=1

.PHONY: help build run run-display run-vnc disk clean

help:
	@echo ""
	@echo "  make build       - Compile the kernel (nasm + cargo)"
	@echo "  make disk        - Create persistent disk image (run once)"
	@echo "  make run         - Boot in QEMU, serial output in terminal (no window)"
	@echo "  make run-display - Boot in QEMU with VGA window + serial in terminal"
	@echo "  make run-vnc     - Boot in QEMU, VNC display on localhost:5900"
	@echo "  make clean       - Remove build artifacts"
	@echo ""
	@echo "  Network: guest 10.0.2.15/24, gateway 10.0.2.2 (QEMU user-net)"
	@echo "  SSH:     host port 2222 → guest port 22"
	@echo "  Connect: ssh root@127.0.0.1 -p 2222   (password: root)"
	@echo "  Try: ping 10.0.2.2   ifconfig   netstat -r   sshd"
	@echo "  Persistence: files created in shell survive reboots (stored in $(DISK))"
	@echo ""

build:
	cargo build

# Create a blank 64 MB disk image for persistent storage (run once).
disk:
	mkdir -p disk
	dd if=/dev/zero of=$(DISK) bs=1M count=64

# Headless: serial output only in this terminal, no graphical window.
run: build
	$(QEMU) \
		-kernel $(BIN) \
		-m 256M \
		-nographic \
		-monitor none \
		-serial stdio \
		$(NET) \
		$(DRIVE)

# Graphical window (SDL): VGA output in a popup window.
# Serial output still appears in this terminal.
run-display: build
	$(QEMU) \
		-kernel $(BIN) \
		-m 256M \
		-display sdl \
		-serial stdio \
		$(NET) \
		$(DRIVE)

# VNC: connect with any VNC viewer to localhost:5900
run-vnc: build
	$(QEMU) \
		-kernel $(BIN) \
		-m 256M \
		-display vnc=:0 \
		-serial stdio \
		$(NET) \
		$(DRIVE)

clean:
	cargo clean
