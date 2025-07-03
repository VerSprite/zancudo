# List of applications to build. The name must match the folder in ./cmd/
BINS := zancudo gen_certs

# Base output directory
BIN_DIR := bin

# Platform-specific output directories
NATIVE_DIR := $(BIN_DIR)/$(shell go env GOOS)_$(shell go env GOARCH)
WINDOWS_DIR := $(BIN_DIR)/windows_amd64
MACOS_AMD64_DIR := $(BIN_DIR)/darwin_amd64
MACOS_ARM64_DIR := $(BIN_DIR)/darwin_arm64

# Platform names for zip files
NATIVE_PLATFORM := $(shell go env GOOS)_$(shell go env GOARCH)
WINDOWS_PLATFORM := windows_amd64
MACOS_AMD64_PLATFORM := darwin_amd64
MACOS_ARM64_PLATFORM := darwin_arm64

# Zip file names
NATIVE_ZIP := $(BIN_DIR)/zancudo-$(NATIVE_PLATFORM).zip
WINDOWS_ZIP := $(BIN_DIR)/zancudo-$(WINDOWS_PLATFORM).zip
MACOS_AMD64_ZIP := $(BIN_DIR)/zancudo-$(MACOS_AMD64_PLATFORM).zip
MACOS_ARM64_ZIP := $(BIN_DIR)/zancudo-$(MACOS_ARM64_PLATFORM).zip

# Define full paths for all target binaries
NATIVE_BINS := $(addprefix $(NATIVE_DIR)/, $(BINS))
WINDOWS_BINS := $(addprefix $(WINDOWS_DIR)/, $(addsuffix .exe, $(BINS)))
MACOS_AMD64_BINS := $(addprefix $(MACOS_AMD64_DIR)/, $(BINS))
MACOS_ARM64_BINS := $(addprefix $(MACOS_ARM64_DIR)/, $(BINS))

# Additional files to include in releases
RELEASE_FILES := README.md ZANCUDO.png LICENSE

.PHONY: all clean native windows macos zips native-zip windows-zip macos-zip

# Build all targets and create zip files
all: zips

# Create zip files for all platforms
zips: native-zip windows-zip macos-zip

# Build for each platform
native: $(NATIVE_BINS)
windows: $(WINDOWS_BINS)
macos: $(MACOS_AMD64_BINS) $(MACOS_ARM64_BINS)

# Create zip files for each platform
native-zip: $(NATIVE_ZIP)
windows-zip: $(WINDOWS_ZIP)
macos-zip: $(MACOS_AMD64_ZIP) $(MACOS_ARM64_ZIP)

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

# --- Zip Creation Rules ---

# Rule for native zip
$(NATIVE_ZIP): $(NATIVE_BINS) $(RELEASE_FILES) | $(BIN_DIR)
	@echo "Creating native release zip $(NATIVE_ZIP)..."
	zip -j $(NATIVE_ZIP) $(NATIVE_BINS) $(RELEASE_FILES)

# Rule for Windows zip
$(WINDOWS_ZIP): $(WINDOWS_BINS) $(RELEASE_FILES) | $(BIN_DIR)
	@echo "Creating Windows release zip $(WINDOWS_ZIP)..."
	zip -j $(WINDOWS_ZIP) $(WINDOWS_BINS) $(RELEASE_FILES)

# Rule for macOS amd64 zip
$(MACOS_AMD64_ZIP): $(MACOS_AMD64_BINS) $(RELEASE_FILES) | $(BIN_DIR)
	@echo "Creating macOS amd64 release zip $(MACOS_AMD64_ZIP)..."
	zip -j $(MACOS_AMD64_ZIP) $(MACOS_AMD64_BINS) $(RELEASE_FILES)

# Rule for macOS arm64 zip
$(MACOS_ARM64_ZIP): $(MACOS_ARM64_BINS) $(RELEASE_FILES) | $(BIN_DIR)
	@echo "Creating macOS arm64 release zip $(MACOS_ARM64_ZIP)..."
	zip -j $(MACOS_ARM64_ZIP) $(MACOS_ARM64_BINS) $(RELEASE_FILES)

# Create the output directories
$(NATIVE_DIR) $(WINDOWS_DIR) $(MACOS_AMD64_DIR) $(MACOS_ARM64_DIR):
	mkdir -p $@

# --- Cleanup ---
clean:
	@echo "Cleaning up generated files..."
	rm -rf $(BIN_DIR)
	rm -f proxy.crt proxy.key client.crt client.key ca.crt ca.key
	@echo "Done."
