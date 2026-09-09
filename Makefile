IMAGE  := fastros-builder
TARGET := x86_64-unknown-none
BIN    := target/$(TARGET)/debug/fastros

.PHONY: help image build run run-vnc clean

help:
	@echo ""
	@echo "  make image     - Build the Docker image (run once)"
	@echo "  make build     - Compile the kernel inside Docker"
	@echo "  make run       - Boot kernel in QEMU (serial output)"
	@echo "  make run-vnc   - Boot kernel in QEMU with VNC on :5900"
	@echo "  make clean     - Remove build artifacts"
	@echo ""

# Build the Docker builder image
image:
	docker build -t $(IMAGE) .

# Compile kernel (nasm + cargo) inside Docker
build:
	docker run --rm \
		-v "$(CURDIR):/app" \
		-w /app \
		$(IMAGE) \
		cargo build

# Run kernel in QEMU - serial output to terminal (no display needed)
run: build
	docker run --rm \
		-v "$(CURDIR):/app" \
		-w /app \
		$(IMAGE) \
		qemu-system-x86_64 \
		  -kernel $(BIN) \
		  -m 256M \
		  -nographic \
		  -serial stdio

# Run kernel with VNC display (connect via VNC viewer to localhost:5900)
run-vnc: build
	docker run --rm \
		-v "$(CURDIR):/app" \
		-w /app \
		-p 5900:5900 \
		$(IMAGE) \
		qemu-system-x86_64 \
		  -kernel $(BIN) \
		  -m 256M \
		  -display vnc=0.0.0.0:0 \
		  -serial stdio

clean:
	cargo clean
