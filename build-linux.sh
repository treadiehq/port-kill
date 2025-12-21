#!/bin/bash

echo "🐧 Building Port Kill for Linux..."

# Check if we're on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "⚠️  Warning: This script is designed for Linux systems"
    echo "   Current OS: $OSTYPE"
    echo "   You can still build, but testing may not work correctly"
    echo ""
fi

# Create a temporary Linux-specific Cargo.toml
echo "📦 Creating Linux-specific build configuration..."

cat > Cargo.linux.tmp.toml << 'EOF'
[package]
name = "port-kill"
version = "0.5.29"
edition = "2021"
authors = ["Treadie <info@treadie.com>"]
description = "A CLI tool to help you find and free ports blocking your dev work, plus manage development caches"
license = "FSL-1.1-MIT"
repository = "https://github.com/treadiehq/port-kill"
build = "build.rs"

[lib]
name = "port_kill"
path = "src/lib.rs"

[[bin]]
name = "port-kill"
path = "src/main_linux.rs"

[[bin]]
name = "port-kill-console"
path = "src/main_console.rs"

[dependencies]
# Platform-agnostic dependencies (used by both GUI and console)
crossbeam-channel = "0.5"
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
serde_yaml = "0.9"
anyhow = "1.0"
thiserror = "1.0"
log = "0.4"
env_logger = "0.10"
clap = { version = "4.0", features = ["derive"] }
regex = "1.0"
sysinfo = "0.30"
chrono = { version = "0.4", features = ["serde"] }
reqwest = { version = "0.11", features = ["json", "blocking"] }
walkdir = "2"

# Unix-specific dependencies (for process management)
nix = { version = "0.27", features = ["signal", "process", "fs"] }

# Linux-specific tray support
libappindicator = "0.7"
gtk = "0.15"

[build-dependencies]
embed-resource = "1.8"

[features]
default = []
embed_icon = []
EOF

# Create a temporary lib.rs that excludes macOS-specific modules
echo "📦 Creating Linux-specific lib.rs..."

cat > src/lib.linux.tmp.rs << 'EOF'
pub mod cache;
pub mod cli;
pub mod console_app;
pub mod endpoint_monitor;
pub mod file_monitor;
pub mod orchestrator;
pub mod port_guard;
pub mod preset_manager;
pub mod process_monitor;
pub mod restart_manager;
pub mod scripting;
pub mod security_audit;
pub mod service_detector;
pub mod smart_filter;
pub mod system_monitor;
pub mod types;
pub mod update_check;

// Exclude macOS-specific modules for Linux build
// pub mod app;
// pub mod tray_menu;
EOF

# Backup current files
if [ -f "Cargo.toml" ]; then
    cp Cargo.toml Cargo.macos.toml.backup
    echo "📦 Backed up macOS Cargo.toml"
fi

if [ -f "src/lib.rs" ]; then
    cp src/lib.rs src/lib.macos.rs.backup
    echo "📦 Backed up macOS lib.rs"
fi

# Switch to Linux configuration
cp Cargo.linux.tmp.toml Cargo.toml
cp src/lib.linux.tmp.rs src/lib.rs
echo "📦 Using Linux configuration"

# Check for required Linux packages
echo "🔍 Checking for required Linux packages..."
if command -v apt-get &> /dev/null; then
    echo "📦 Detected Debian/Ubuntu system"
    echo "💡 To install required packages:"
    echo "   sudo apt-get install libatk1.0-dev libgdk-pixbuf2.0-dev libgtk-3-dev libayatana-appindicator3-dev"
elif command -v dnf &> /dev/null; then
    echo "📦 Detected Fedora/RHEL system"
    echo "💡 To install required packages:"
    echo "   sudo dnf install atk-devel gdk-pixbuf2-devel gtk3-devel libayatana-appindicator3-devel"
elif command -v pacman &> /dev/null; then
    echo "📦 Detected Arch Linux system"
    echo "💡 To install required packages:"
    echo "   sudo pacman -S atk gdk-pixbuf2 gtk3 libayatana-appindicator3"
else
    echo "⚠️  Unknown package manager, please install GTK development packages manually"
fi
echo ""

# Build the Linux version
echo "🔨 Building with cargo..."
cargo build --release

if [ $? -eq 0 ]; then
    echo "✅ Linux version built successfully!"
    echo "📦 Binary location: ./target/release/port-kill"
    echo "📦 Console binary: ./target/release/port-kill-console"
    echo ""
    echo "🧪 To test:"
    echo "   ./target/release/port-kill --console --ports 3000,8000 --verbose"
    echo ""
    echo "💡 Note: Console mode works without GUI dependencies"
    echo "   System tray mode requires GTK development packages"
    
    # Clean up temporary files
    rm Cargo.linux.tmp.toml src/lib.linux.tmp.rs
    
    # Restore macOS configuration
    if [ -f "Cargo.macos.toml.backup" ]; then
        cp Cargo.macos.toml.backup Cargo.toml
        echo "📦 Restored macOS Cargo.toml"
    fi
    
    if [ -f "src/lib.macos.rs.backup" ]; then
        cp src/lib.macos.rs.backup src/lib.rs
        echo "📦 Restored macOS lib.rs"
    fi
else
    echo "❌ Build failed!"
    echo ""
    echo "💡 Common solutions:"
    echo "   1. Install required packages (see above)"
    echo "   2. Try console mode: ./target/release/port-kill-console --console --ports 3000,8000"
    
    # Clean up temporary files
    rm Cargo.linux.tmp.toml src/lib.linux.tmp.rs
    
    # Restore macOS configuration
    if [ -f "Cargo.macos.toml.backup" ]; then
        cp Cargo.macos.toml.backup Cargo.toml
        echo "📦 Restored macOS Cargo.toml"
    fi
    
    if [ -f "src/lib.macos.rs.backup" ]; then
        cp src/lib.macos.rs.backup src/lib.rs
        echo "📦 Restored macOS lib.rs"
    fi
    
    exit 1
fi
