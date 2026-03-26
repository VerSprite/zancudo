# List of applications to build. The name must match the folder in ./cmd/
BINS := zancudo gen_certs

# Base output directories
BIN_DIR := bin
DIST_DIR := dist

# Platform-specific output directories
LINUX_AMD64_DIR := $(BIN_DIR)/linux_amd64
WINDOWS_DIR := $(BIN_DIR)/windows_amd64
MACOS_AMD64_DIR := $(BIN_DIR)/darwin_amd64
MACOS_ARM64_DIR := $(BIN_DIR)/darwin_arm64

# Platform names for zip files
LINUX_AMD64_PLATFORM := linux_amd64
WINDOWS_PLATFORM := windows_amd64
MACOS_AMD64_PLATFORM := darwin_amd64
MACOS_ARM64_PLATFORM := darwin_arm64

# Zip file names (release artifacts under dist/)
LINUX_AMD64_ZIP := $(DIST_DIR)/zancudo-$(LINUX_AMD64_PLATFORM).zip
WINDOWS_ZIP := $(DIST_DIR)/zancudo-$(WINDOWS_PLATFORM).zip
MACOS_AMD64_ZIP := $(DIST_DIR)/zancudo-$(MACOS_AMD64_PLATFORM).zip
MACOS_ARM64_ZIP := $(DIST_DIR)/zancudo-$(MACOS_ARM64_PLATFORM).zip

# Define full paths for all target binaries
LINUX_AMD64_BINS := $(addprefix $(LINUX_AMD64_DIR)/, $(BINS))
WINDOWS_BINS := $(addprefix $(WINDOWS_DIR)/, $(addsuffix .exe, $(BINS)))
MACOS_AMD64_BINS := $(addprefix $(MACOS_AMD64_DIR)/, $(BINS))
MACOS_ARM64_BINS := $(addprefix $(MACOS_ARM64_DIR)/, $(BINS))

# Additional files to include in releases
RELEASE_FILES := README.md ZANCUDO.png LICENSE

.DEFAULT_GOAL := help

.PHONY: help all clean linux windows macos zips linux-zip windows-zip macos-zip \
	ci-tools ci-check ci-fix _ci_binaries

# ANSI colors: used only by the `help` target (bold cyan title, yellow sections, green commands, dim hints).
help:
	@printf '%b\n' '\033[1;36mZancudo Makefile\033[0m' '' \
		'\033[2mRunning make with no target shows this help (default).\033[0m' '' \
		'\033[1;33mRelease builds\033[0m \033[2m(binaries under bin/, zips under dist/):\033[0m' \
		'  \033[1;32mmake all\033[0m          Same as zips: all platform zips + binaries' \
		'  \033[1;32mmake zips\033[0m         linux-zip, windows-zip, macos-zip' \
		'  \033[1;32mmake linux\033[0m        Linux amd64 binaries only' \
		'  \033[1;32mmake windows\033[0m      Windows amd64 binaries only' \
		'  \033[1;32mmake macos\033[0m        Mac OS amd64 + arm64 binaries only' \
		'  \033[1;32mmake linux-zip\033[0m    Linux zip only (needs linux + README assets)' \
		'  \033[1;32mmake windows-zip\033[0m  Windows zip only' \
		'  \033[1;32mmake macos-zip\033[0m    Mac OS zips only' '' \
		'\033[1;33mCode quality\033[0m \033[2m(mirrors .github/workflows/ci.yml; needs Go per cmd/*/go.mod):\033[0m' \
		'  \033[1;32mmake ci-tools\033[0m     Install goimports, golangci-lint, govulncheck to GOBIN/GOPATH/bin' \
		'  \033[1;32mmake ci-check\033[0m     goimports -l, golangci-lint --enable=gosec, govulncheck per module' \
		'  \033[1;32mmake ci-fix\033[0m       goimports -w, golangci-lint --fix, then govulncheck (vulns: report only)' '' \
		'\033[1;33mOther\033[0m' \
		'  \033[1;32mmake clean\033[0m        Remove bin/, dist/, and generated cert files in repo root' ''

# --- CI parity (same checks as .github/workflows/ci.yml) ---
GO_MODULES := $(addprefix cmd/,$(BINS))
GOPATH := $(shell go env GOPATH)
GOBIN := $(shell go env GOBIN)
CI_BIN := $(if $(strip $(GOBIN)),$(GOBIN),$(GOPATH)/bin)
GOIMPORTS := $(CI_BIN)/goimports
GOLANGCI_LINT := $(CI_BIN)/golangci-lint
GOVULNCHECK := $(CI_BIN)/govulncheck
GOIMPORTS_LOCAL := github.com/VerSprite
# golangci-lint must be built with a toolchain >= the `go` line in cmd/zancudo/go.mod.
CI_GO_TOOLCHAIN := go$(shell awk '/^go / { print $$2; exit }' cmd/zancudo/go.mod)

_ci_binaries:
	@test -x '$(GOIMPORTS)' && test -x '$(GOLANGCI_LINT)' && test -x '$(GOVULNCHECK)' || \
		(echo 'Missing tools; install with: make ci-tools' >&2; exit 1)

ci-tools:
	cd cmd/zancudo && GOTOOLCHAIN=$(CI_GO_TOOLCHAIN) go install golang.org/x/tools/cmd/goimports@latest
	cd cmd/zancudo && GOTOOLCHAIN=$(CI_GO_TOOLCHAIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	cd cmd/zancudo && GOTOOLCHAIN=$(CI_GO_TOOLCHAIN) go install golang.org/x/vuln/cmd/govulncheck@latest

# Verify: goimports, golangci-lint (incl. gosec), govulncheck per module under cmd/*
ci-check: _ci_binaries
	@set -e; \
	for m in $(GO_MODULES); do \
		echo "== goimports $$m =="; \
		out="$$( cd $$m && '$(GOIMPORTS)' -local $(GOIMPORTS_LOCAL) -l . )"; \
		if [ -n "$$out" ]; then \
			echo 'The following files need goimports (or gofmt):'; \
			echo "$$out"; \
			exit 1; \
		fi; \
	done
	@set -e; \
	for m in $(GO_MODULES); do \
		echo "== golangci-lint $$m =="; \
		( cd $$m && '$(GOLANGCI_LINT)' run --enable=gosec ); \
	done
	@set -e; \
	for m in $(GO_MODULES); do \
		echo "== govulncheck $$m =="; \
		( cd $$m && '$(GOVULNCHECK)' ./... ); \
	done
	@echo 'ci-check: OK'

# Auto-fix: goimports -w and golangci-lint --fix; then govulncheck (check only, no auto-fix)
ci-fix: _ci_binaries
	@set -e; \
	for m in $(GO_MODULES); do \
		echo "== goimports -w $$m =="; \
		( cd $$m && '$(GOIMPORTS)' -local $(GOIMPORTS_LOCAL) -w . ); \
	done
	@set -e; \
	for m in $(GO_MODULES); do \
		echo "== golangci-lint --fix $$m =="; \
		( cd $$m && '$(GOLANGCI_LINT)' run --enable=gosec --fix ); \
	done
	@set -e; \
	for m in $(GO_MODULES); do \
		echo "== govulncheck $$m =="; \
		( cd $$m && '$(GOVULNCHECK)' ./... ); \
	done
	@echo 'ci-fix: OK'

# Build all targets and create zip files
all: zips

# Create zip files for all platforms
zips: linux-zip windows-zip macos-zip

# Build for each platform
linux: $(LINUX_AMD64_BINS)
windows: $(WINDOWS_BINS)
macos: $(MACOS_AMD64_BINS) $(MACOS_ARM64_BINS)

# Create zip files for each platform
linux-zip: $(LINUX_AMD64_ZIP)
windows-zip: $(WINDOWS_ZIP)
macos-zip: $(MACOS_AMD64_ZIP) $(MACOS_ARM64_ZIP)

# --- Build Rules ---

# Rule for Linux amd64 binaries
$(LINUX_AMD64_BINS): $(LINUX_AMD64_DIR)/%: | $(LINUX_AMD64_DIR)
	@echo "Building Linux amd64 binary for $*..."
	(cd ./cmd/$* && GOOS=linux GOARCH=amd64 go build -o ../../$@ .)

# Rule for Windows binaries
$(WINDOWS_BINS): $(WINDOWS_DIR)/%.exe: | $(WINDOWS_DIR)
	@echo "Building Windows binary for $*..."
	(cd ./cmd/$* && GOOS=windows GOARCH=amd64 go build -o ../../$@ .)

# Rule for macOS amd64 binaries
$(MACOS_AMD64_BINS): $(MACOS_AMD64_DIR)/%: | $(MACOS_AMD64_DIR)
	@echo "Building macOS amd64 binary for $*..."
	(cd ./cmd/$* && GOOS=darwin GOARCH=amd64 go build -o ../../$@ .)

# Rule for macOS arm64 binaries
$(MACOS_ARM64_BINS): $(MACOS_ARM64_DIR)/%: | $(MACOS_ARM64_DIR)
	@echo "Building macOS arm64 binary for $*..."
	(cd ./cmd/$* && GOOS=darwin GOARCH=arm64 go build -o ../../$@ .)

# --- Zip Creation Rules ---

# Rule for Linux amd64 zip
$(LINUX_AMD64_ZIP): $(LINUX_AMD64_BINS) $(RELEASE_FILES) | $(DIST_DIR)
	@echo "Creating Linux amd64 release zip $(LINUX_AMD64_ZIP)..."
	zip -j $(LINUX_AMD64_ZIP) $(LINUX_AMD64_BINS) $(RELEASE_FILES)

# Rule for Windows zip
$(WINDOWS_ZIP): $(WINDOWS_BINS) $(RELEASE_FILES) | $(DIST_DIR)
	@echo "Creating Windows release zip $(WINDOWS_ZIP)..."
	zip -j $(WINDOWS_ZIP) $(WINDOWS_BINS) $(RELEASE_FILES)

# Rule for macOS amd64 zip
$(MACOS_AMD64_ZIP): $(MACOS_AMD64_BINS) $(RELEASE_FILES) | $(DIST_DIR)
	@echo "Creating macOS amd64 release zip $(MACOS_AMD64_ZIP)..."
	zip -j $(MACOS_AMD64_ZIP) $(MACOS_AMD64_BINS) $(RELEASE_FILES)

# Rule for macOS arm64 zip
$(MACOS_ARM64_ZIP): $(MACOS_ARM64_BINS) $(RELEASE_FILES) | $(DIST_DIR)
	@echo "Creating macOS arm64 release zip $(MACOS_ARM64_ZIP)..."
	zip -j $(MACOS_ARM64_ZIP) $(MACOS_ARM64_BINS) $(RELEASE_FILES)

# Create the output directories
$(LINUX_AMD64_DIR) $(WINDOWS_DIR) $(MACOS_AMD64_DIR) $(MACOS_ARM64_DIR) $(DIST_DIR):
	mkdir -p $@

# --- Cleanup ---
clean:
	@echo "Cleaning up generated files..."
	rm -rf $(BIN_DIR) $(DIST_DIR)
	rm -f proxy.crt proxy.key client.crt client.key ca.crt ca.key
	@echo "Done."
