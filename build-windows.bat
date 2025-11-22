@echo off
echo 🪟 Building Port Kill for Windows...

REM Check if we're on Windows
if not "%OS%"=="Windows_NT" (
    echo ⚠️  Warning: This script is designed for Windows systems
    echo    Current OS: %OS%
    echo    You can still build, but testing may not work correctly
    echo.
)

REM Check if Rust is installed
rustc --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Rust is not installed or not in PATH
    echo    Please install Rust from https://rustup.rs/
    exit /b 1
)

REM Create a temporary Windows-specific Cargo.toml
echo 📦 Creating Windows-specific build configuration...

(
echo [package]
echo name = "port-kill"
echo version = "0.5.28"
echo edition = "2021"
echo authors = ["Treadie ^<info@treadie.com^>"]
echo description = "A CLI tool to help you find and free ports blocking your dev work, plus manage development caches"
echo license = "FSL-1.1-MIT"
echo repository = "https://github.com/treadiehq/port-kill"
echo build = "build.rs"
echo.
echo [lib]
echo name = "port_kill"
echo path = "src/lib.rs"
echo.
echo [[bin]]
echo name = "port-kill"
echo path = "src/main_windows.rs"
echo.
echo [[bin]]
echo name = "port-kill-console"
echo path = "src/main_console.rs"
echo.
echo [dependencies]
echo # Platform-agnostic dependencies ^(used by both GUI and console^)
echo crossbeam-channel = "0.5"
echo tokio = { version = "1.0", features = ["full"] }
echo serde = { version = "1.0", features = ["derive"] }
echo serde_json = "1.0"
echo serde_yaml = "0.9"
echo anyhow = "1.0"
echo thiserror = "1.0"
echo log = "0.4"
echo env_logger = "0.10"
echo clap = { version = "4.0", features = ["derive"] }
echo regex = "1.0"
echo sysinfo = "0.30"
echo chrono = { version = "0.4", features = ["serde"] }
echo reqwest = { version = "0.11", features = ["json", "blocking"] }
echo walkdir = "2"
echo.
echo # Windows-specific tray support
echo tray-item = "0.10.0"
echo.
echo [build-dependencies]
echo embed-resource = "1.8"
echo.
echo [features]
echo default = []
echo embed_icon = []
) > Cargo.windows.tmp.toml

REM Create a temporary lib.rs that excludes macOS/Linux-specific modules
echo 📦 Creating Windows-specific lib.rs...

(
echo pub mod cache;
echo pub mod cli;
echo pub mod console_app;
echo pub mod endpoint_monitor;
echo pub mod file_monitor;
echo pub mod orchestrator;
echo pub mod port_guard;
echo pub mod preset_manager;
echo pub mod process_monitor;
echo pub mod restart_manager;
echo pub mod scripting;
echo pub mod security_audit;
echo pub mod service_detector;
echo pub mod smart_filter;
echo pub mod system_monitor;
echo pub mod types;
echo pub mod update_check;
) > src/lib.windows.tmp.rs

REM Backup current files
if exist "Cargo.toml" (
    copy "Cargo.toml" "Cargo.macos.toml.backup" >nul
    echo 📦 Backed up macOS Cargo.toml
)

if exist "src\lib.rs" (
    copy "src\lib.rs" "src\lib.macos.rs.backup" >nul
    echo 📦 Backed up macOS lib.rs
)

REM Switch to Windows configuration
copy "Cargo.windows.tmp.toml" "Cargo.toml" >nul
copy "src\lib.windows.tmp.rs" "src\lib.rs" >nul
echo 📦 Using Windows configuration

REM Build the Windows version
echo 🔨 Building with cargo...
cargo build --release --features embed_icon

if errorlevel 1 (
    echo ❌ Build failed!
    echo.
    echo 💡 Common solutions:
    echo    1. Install Rust and Cargo
    echo    2. Try console mode: .\target\release\port-kill-console.exe --console --ports 3000,8000
    
    REM Clean up temporary files
    del "Cargo.windows.tmp.toml" >nul 2>&1
    del "src\lib.windows.tmp.rs" >nul 2>&1
    
    REM Restore macOS configuration
    if exist "Cargo.macos.toml.backup" (
        copy "Cargo.macos.toml.backup" "Cargo.toml" >nul
        echo 📦 Restored macOS Cargo.toml
    )
    
    if exist "src\lib.macos.rs.backup" (
        copy "src\lib.macos.rs.backup" "src\lib.rs" >nul
        echo 📦 Restored macOS lib.rs
    )
    
    exit /b 1
) else (
    echo ✅ Windows version built successfully!
    echo 📦 Binary location: .\target\release\port-kill.exe
    echo 📦 Console binary: .\target\release\port-kill-console.exe
    echo.
    echo 🧪 To test:
    echo    .\target\release\port-kill.exe --console --ports 3000,8000 --verbose
    echo.
    echo 💡 Note: Console mode works without GUI dependencies
    echo    System tray mode requires Windows system tray support
    
    REM Clean up temporary files
    del "Cargo.windows.tmp.toml" >nul 2>&1
    del "src\lib.windows.tmp.rs" >nul 2>&1
    
    REM Restore macOS configuration
    if exist "Cargo.macos.toml.backup" (
        copy "Cargo.macos.toml.backup" "Cargo.toml" >nul
        echo 📦 Restored macOS Cargo.toml
    )
    
    if exist "src\lib.macos.rs.backup" (
        copy "src\lib.macos.rs.backup" "src\lib.rs" >nul
        echo 📦 Restored macOS lib.rs
    )
)
