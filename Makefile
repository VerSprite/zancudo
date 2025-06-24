# List of applications to build. The name must match the folder in ./cmd/
BINS := mqtt_mitm_proxy gen_certs

# Base output directory
BIN_DIR := bin

# Platform-specific output directories
NATIVE_DIR := $(BIN_DIR)/$(shell go env GOOS)_$(shell go env GOARCH)
WINDOWS_DIR := $(BIN_DIR)/windows_amd64
MACOS_AMD64_DIR := $(BIN_DIR)/darwin_amd64
MACOS_ARM64_DIR := $(BIN_DIR)/darwin_arm64

# Define full paths for all target binaries
NATIVE_BINS := $(addprefix $(NATIVE_DIR)/, $(BINS))
WINDOWS_BINS := $(addprefix $(WINDOWS_DIR)/, $(addsuffix .exe, $(BINS)))
MACOS_AMD64_BINS := $(addprefix $(MACOS_AMD64_DIR)/, $(BINS))
MACOS_ARM64_BINS := $(addprefix $(MACOS_ARM64_DIR)/, $(BINS))

.PHONY: all clean native windows macos

# Build all targets
all: native windows macos

# Build for each platform
native: $(NATIVE_BINS)
windows: $(WINDOWS_BINS)
macos: $(MACOS_AMD64_BINS) $(MACOS_ARM64_BINS)

# --- Build Rules ---

# Rule for native binaries
$(NATIVE_BINS): $(NATIVE_DIR)/%: | $(NATIVE_DIR)
	@echo "Building native binary for $*..."
	(cd ./cmd/$* && go build -o ../../$@ .)

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

# Create the output directories
$(NATIVE_DIR) $(WINDOWS_DIR) $(MACOS_AMD64_DIR) $(MACOS_ARM64_DIR):
	mkdir -p $@

# --- Cleanup ---
clean:
	@echo "Cleaning up generated files..."
	rm -rf $(BIN_DIR)
	rm -f proxy.crt proxy.key client.crt client.key ca.crt ca.key
	@echo "Done."
