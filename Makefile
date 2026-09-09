TARGET := x86_64-unknown-none
BIN    := target/$(TARGET)/debug/fastros
QEMU   := "C:/Program Files/QEMU/qemu-system-x86_64.exe"

.PHONY: help build run clean

help:
	@echo ""
	@echo "  make build   - Compile the kernel (nasm + cargo, native)"
	@echo "  make run     - Boot kernel in QEMU (serial output)"
	@echo "  make clean   - Remove build artifacts"
	@echo ""

build:
	cargo build

run: build
	$(QEMU) \
		-kernel $(BIN) \
		-m 256M \
		-nographic \
		-monitor none \
		-serial stdio

clean:
	cargo clean
