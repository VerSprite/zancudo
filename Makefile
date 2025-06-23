BINS := mqtt_mitm_proxy gen_certs

# Native (Linux) binaries
NATIVE_BINS := $(BINS)

# Windows binaries
WINDOWS_BINS := $(addsuffix .exe,$(BINS))

# macOS binaries for Intel (amd64)
MACOS_AMD64_BINS := $(addsuffix _darwin_amd64,$(BINS))

# macOS binaries for Apple Silicon (arm64)
MACOS_ARM64_BINS := $(addsuffix _darwin_arm64,$(BINS))

.PHONY: all clean native windows macos

all: native windows macos

native: $(NATIVE_BINS)
windows: $(WINDOWS_BINS)
macos: $(MACOS_AMD64_BINS) $(MACOS_ARM64_BINS)

# Pattern rule for native binaries
$(NATIVE_BINS): %: %.go
	go build -o $@ $<

# Pattern rule for Windows binaries
$(WINDOWS_BINS): %.exe: %.go
	GOOS=windows GOARCH=amd64 go build -o $@ $<

# Pattern rule for macOS amd64 binaries
$(MACOS_AMD64_BINS): %_darwin_amd64: %.go
	GOOS=darwin GOARCH=amd64 go build -o $@ $<

# Pattern rule for macOS arm64 binaries
$(MACOS_ARM64_BINS): %_darwin_arm64: %.go
	GOOS=darwin GOARCH=arm64 go build -o $@ $<

# Clean up generated binaries and certificates
clean:
	rm -f $(NATIVE_BINS) $(WINDOWS_BINS) $(MACOS_AMD64_BINS) $(MACOS_ARM64_BINS) proxy.crt proxy.key ca.crt ca.key
