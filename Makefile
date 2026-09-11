# Everything runs in Docker — the host needs only Docker (and make, for these
# shortcuts; without make, run the commands on the right directly).
#
# Guest network: 10.0.2.15/24, gateway 10.0.2.2 (QEMU user-net).
# SSH: host port 2323 -> guest port 22. Files survive reboots (./disk/data.img).

IMAGE := fastros
MEM   ?= 256M

# Pass /dev/kvm through only when the host has it (Linux x86_64); elsewhere
# the container falls back to TCG emulation on its own.
KVM := $(if $(wildcard /dev/kvm),--device /dev/kvm,)

.PHONY: help build up ssh logs down test kernel clean

help:
	@echo ""
	@echo "  make build   - Build the image (compiles the kernel inside Docker)"
	@echo "  make up      - Boot FastROS in the background"
	@echo "  make ssh     - Log in: ssh root@localhost -p 2323 (password: root)"
	@echo "  make logs    - Follow the serial console / kernel log"
	@echo "  make down    - Power off (./disk is kept)"
	@echo "  make test    - Boot smoke test: logs in over SSH, checks the answer"
	@echo "  make kernel  - Copy the kernel binary out to ./out/fastros"
	@echo "  make clean   - Remove the container and the image (./disk is kept)"
	@echo ""
	@echo "  Try: ping 10.0.2.2   ifconfig   netstat -r   htop"
	@echo ""

build:
	docker compose build

up:
	docker compose up -d --build

ssh:
	ssh root@localhost -p 2323

logs:
	docker compose logs -f fastros

down:
	docker compose down

test: build
	docker run --rm $(KVM) -e FASTROS_MEM=$(MEM) $(IMAGE) test

kernel:
	docker build --target kernel --output out .

clean:
	docker compose down --rmi all
