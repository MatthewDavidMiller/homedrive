# homedrive build system
# Usage: make [target]

.PHONY: help install fmt lint test test-image image release shell clean

# Every gate runs inside the toolbox image, so rootless Podman is the only
# thing this repository needs from a workstation.
TOOLBOX := ./scripts/toolbox.sh

help:
	@echo "homedrive"
	@echo ""
	@echo "  install   Build the toolbox image and install the git hooks (once)"
	@echo "  fmt       Format the Rust sources"
	@echo "  lint      shellcheck the scripts and hooks"
	@echo "  test      The full pre-commit gate: lint, rustfmt, dependency"
	@echo "            graph, unsafe allowlist, clippy, and the test suites"
	@echo "  image     Build the runtime image localhost/homedrive:dev"
	@echo "  test-image  Build the image and run it, and the end-to-end tests,"
	@echo "            with VM1's security flags (slow; pulls nothing new)"
	@echo "  release   Gate, build, push to GHCR, tag, and create the GitHub release"
	@echo "  shell     Interactive shell in the toolbox"
	@echo "  clean     Remove build output"
	@echo ""
	@echo "Prerequisite: rootless Podman. Nothing else."

install:
	$(TOOLBOX) --build
	./scripts/setup-hooks.sh

fmt:
	$(TOOLBOX) cargo fmt --all

lint:
	$(TOOLBOX) ./scripts/lint.sh

test:
	$(TOOLBOX) ./scripts/test-local.sh

image:
	podman build --format docker --platform linux/amd64 -f Containerfile -t localhost/homedrive:dev .

test-image:
	./scripts/test-image.sh

release:
	./scripts/release.sh

shell:
	$(TOOLBOX) --shell

clean:
	rm -rf target .build dist
