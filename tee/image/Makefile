.PHONY: help build clean run-qemu extract-boot-artifacts extract-uki

IMAGE_VERSION ?= $(shell grep '^ImageVersion=' mkosi.conf | cut -d= -f2)
DISK_IMAGE_RAW=tacet_$(IMAGE_VERSION).raw
DISK_IMAGE=tacet_$(IMAGE_VERSION).qcow2
UKI_IMAGE=tacet_$(IMAGE_VERSION).efi
KERNEL_IMAGE=tacet_$(IMAGE_VERSION).vmlinuz
INITRD_IMAGE=tacet_$(IMAGE_VERSION).initrd
CMDLINE_FILE=tacet_$(IMAGE_VERSION).cmdline

help:
	@echo "Tacet Image Builder"
	@echo "==================="
	@echo ""
	@echo "Targets:"
	@echo "  make build                  - Build VM disk image"
	@echo "  make clean                  - Remove build artifacts"
	@echo "  make run-qemu               - Boot image in QEMU (CPU, for testing)"
	@echo "  make extract-boot-artifacts - Extract kernel, initrd, cmdline from UKI"
	@echo ""
	@echo "Output:"
	@echo "  $(KERNEL_IMAGE)  - Linux kernel"
	@echo "  $(INITRD_IMAGE)  - Initial ramdisk"
	@echo "  $(DISK_IMAGE)    - Root filesystem (qcow2)"
	@echo "  $(CMDLINE_FILE)  - Kernel command line"
	@echo ""

build:
	@echo "Building Tacet VM image..."
	@echo "Image version: $(IMAGE_VERSION)"
	sudo $$(which mkosi) --force --image-version=$(IMAGE_VERSION)
	@echo ""
	@echo "Extracting boot artifacts..."
	@$(MAKE) extract-boot-artifacts
	@echo ""
	@echo "Converting to qcow2..."
	@qemu-img convert -f raw -O qcow2 -c $(DISK_IMAGE_RAW) $(DISK_IMAGE)
	@echo "Done: $(DISK_IMAGE) ($$(du -h $(DISK_IMAGE) | cut -f1))"

extract-uki:
	@echo "Extracting UKI from ESP..."
	@if [ ! -f $(DISK_IMAGE_RAW) ]; then \
		echo "Error: $(DISK_IMAGE_RAW) not found. Run 'make build' first."; \
		exit 1; \
	fi
	@ESP_START=$$(sfdisk -J $(DISK_IMAGE_RAW) | python3 -c "import json,sys; parts=json.load(sys.stdin)['partitiontable']['partitions']; print(next(p['start'] for p in parts if p.get('type','').upper() == 'C12A7328-F81F-11D2-BA4B-00A0C93EC93B'))") && \
	ESP_SIZE=$$(sfdisk -J $(DISK_IMAGE_RAW) | python3 -c "import json,sys; parts=json.load(sys.stdin)['partitiontable']['partitions']; print(next(p['size'] for p in parts if p.get('type','').upper() == 'C12A7328-F81F-11D2-BA4B-00A0C93EC93B'))") && \
	rm -rf .esp-mount && mkdir -p .esp-mount && \
	sudo mount -o loop,offset=$$((ESP_START * 512)),sizelimit=$$((ESP_SIZE * 512)),ro $(DISK_IMAGE_RAW) .esp-mount && \
	UKI_PATH=$$(find .esp-mount -name '*.efi' -path '*/EFI/Linux/*' | head -1) && \
	if [ -z "$$UKI_PATH" ]; then \
		UKI_PATH=$$(find .esp-mount -name '*.efi' -path '*/EFI/*' | head -1); \
	fi && \
	sudo cp "$$UKI_PATH" $(UKI_IMAGE) && \
	sudo chown $$(id -u):$$(id -g) $(UKI_IMAGE) && \
	sudo umount .esp-mount && \
	rm -rf .esp-mount && \
	echo "UKI: $(UKI_IMAGE)"

extract-boot-artifacts: extract-uki
	@echo "Extracting boot artifacts from UKI..."
	objcopy --dump-section .linux=$(KERNEL_IMAGE) \
	        --dump-section .initrd=$(INITRD_IMAGE) \
	        --dump-section .cmdline=.cmdline.raw \
	        $(UKI_IMAGE)
	@cat .cmdline.raw | tr -d '\0' > $(CMDLINE_FILE)
	@rm -f .cmdline.raw
	@echo "Kernel:  $(KERNEL_IMAGE) ($$(du -h $(KERNEL_IMAGE) | cut -f1))"
	@echo "Initrd:  $(INITRD_IMAGE) ($$(du -h $(INITRD_IMAGE) | cut -f1))"
	@echo "Cmdline: $$(cat $(CMDLINE_FILE))"

# Boot in QEMU for local testing (CPU only, no GPU)
# Pass MODEL_DIR to share a host directory with model weights
MODEL_DIR ?= /tmp/models
run-qemu:
	@if [ ! -f $(KERNEL_IMAGE) ]; then \
		echo "Error: Boot artifacts not found. Run 'make build' first."; \
		exit 1; \
	fi
	qemu-system-x86_64 \
		-kernel $(KERNEL_IMAGE) \
		-initrd $(INITRD_IMAGE) \
		-drive file=$(DISK_IMAGE),format=qcow2,if=virtio \
		-append "$$(cat $(CMDLINE_FILE)) root=/dev/vda2 rw console=ttyS0" \
		-m 8G \
		-smp 4 \
		-nographic \
		-enable-kvm \
		-nic user,hostfwd=tcp::8000-:8000

clean:
	@echo "Cleaning..."
	@rm -rf mkosi.output/ mkosi.cache/ mkosi.extra/ .esp-mount/
	@rm -f $(DISK_IMAGE) $(DISK_IMAGE_RAW) $(UKI_IMAGE)
	@rm -f $(KERNEL_IMAGE) $(INITRD_IMAGE) $(CMDLINE_FILE)
	@rm -f .skeleton-hash .cmdline.raw
	@echo "Clean complete"
