# Makefile for passivednsgo

# Binary name
BINARY_NAME=passivednsgo
# Build directory
BUILD_DIR=bin
# Main entry point
MAIN_PATH=cmd/passivednsgo/main.go

# Installation Paths
INSTALL_BIN=/usr/local/bin
CONFIG_DIR=/etc/passivednsgo
SYSTEMD_DIR=/etc/systemd/system

.PHONY: all build clean test run install deps fmt

all: build

# Install dependencies
deps:
	go mod tidy
	go mod download

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PATH)

# Run the application (useful for dev)
run:
	go run $(MAIN_PATH)

# Run tests
test:
	go test -v ./...

# Clean build artifacts
clean:
	@echo "Cleaning..."
	go clean
	rm -rf $(BUILD_DIR)

# Format code
fmt:
	go fmt ./...

# Install binary, config, and systemd service (Run with sudo)
install: build
	@echo "Installing binary to $(INSTALL_BIN)..."
	install -m 755 $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_BIN)/
	
	@echo "Installing configuration to $(CONFIG_DIR)..."
	mkdir -p $(CONFIG_DIR)
	# Only overwrite if it doesn't exist, or force it? 
	# usually 'install' overwrites. Be careful in production updates!
	install -m 644 deploy/passivednsgo.yaml $(CONFIG_DIR)/passivednsgo.yaml
	
	@echo "Installing systemd service..."
	install -m 644 deploy/passivednsgo.service $(SYSTEMD_DIR)/
	
	@echo "Installation complete."
	@echo "1. Edit config: $(CONFIG_DIR)/passivednsgo.yaml"
	@echo "2. Reload systemd: systemctl daemon-reload"
	@echo "3. Start service: systemctl enable --now passivednsgo"
