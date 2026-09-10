TARGET := x86_64-unknown-none
BIN    := target/$(TARGET)/debug/fastros
QEMU   := "C:/Program Files/QEMU/qemu-system-x86_64.exe"

.PHONY: help build run run-display run-vnc clean

help:
	@echo ""
	@echo "  make build       - Compile the kernel (nasm + cargo)"
	@echo "  make run         - Boot in QEMU, serial output in terminal (no window)"
	@echo "  make run-display - Boot in QEMU with VGA window + serial in terminal"
	@echo "  make run-vnc     - Boot in QEMU, VNC display on localhost:5900"
	@echo "  make clean       - Remove build artifacts"
	@echo ""

build:
	cargo build

# Headless: serial output only in this terminal, no graphical window.
run: build
	$(QEMU) \
		-kernel $(BIN) \
		-m 256M \
		-nographic \
		-monitor none \
		-serial stdio

# Graphical window (SDL): VGA output in a popup window.
# Serial output still appears in this terminal.
run-display: build
	$(QEMU) \
		-kernel $(BIN) \
		-m 256M \
		-display sdl \
		-serial stdio

# VNC: connect with any VNC viewer to localhost:5900
run-vnc: build
	$(QEMU) \
		-kernel $(BIN) \
		-m 256M \
		-display vnc=:0 \
		-serial stdio

clean:
	cargo clean
