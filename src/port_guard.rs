use anyhow::Result;
use chrono::{Duration, Utc};
use log::{info, warn};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration as TokioDuration};

use crate::process_monitor::ProcessMonitor;
use crate::types::{
    GuardStatus, PortConflict, PortConflictType, PortReservation, PortResolution, ProcessInfo,
};
use std::collections::HashSet;

/// Port Guard daemon that proactively prevents port conflicts
pub struct PortGuardDaemon {
    watched_ports: Vec<u16>,
    reservations: Arc<Mutex<HashMap<u16, PortReservation>>>,
    reservation_file: String,
    auto_resolve: bool,
    auto_restart: bool,
    conflicts_resolved: Arc<Mutex<usize>>,
    is_running: Arc<Mutex<bool>>,
    process_monitor: Arc<Mutex<ProcessMonitor>>,
    intercepted_commands: Arc<Mutex<HashSet<String>>>,
    process_interception_enabled: bool,
    allowed_process_name: Option<String>,
}

impl PortGuardDaemon {
    /// Create a new Port Guard daemon
    pub fn new(
        watched_ports: Vec<u16>,
        reservation_file: String,
        auto_resolve: bool,
        process_monitor: Arc<Mutex<ProcessMonitor>>,
    ) -> Self {
        Self {
            watched_ports,
            reservations: Arc::new(Mutex::new(HashMap::new())),
            reservation_file,
            auto_resolve,
            auto_restart: false,
            conflicts_resolved: Arc::new(Mutex::new(0)),
            is_running: Arc::new(Mutex::new(false)),
            process_monitor,
            intercepted_commands: Arc::new(Mutex::new(HashSet::new())),
            process_interception_enabled: true,
            allowed_process_name: None,
        }
    }

    /// Set an allowed process name for guard enforcement
    pub fn set_allowed_process_name(&mut self, name: String) {
        self.allowed_process_name = Some(name);
    }

    /// Enable or disable auto-restart
    pub fn set_auto_restart(&mut self, enabled: bool) {
        self.auto_restart = enabled;
    }

    /// Start the Port Guard daemon
    pub async fn start(&self) -> Result<()> {
        // Load existing reservations
        self.load_reservations().await?;

        // Mark as running
        {
            let mut running = self.is_running.lock().await;
            *running = true;
        }

        info!(
            "🛡️  Port Guard daemon started, watching ports: {:?}",
            self.watched_ports
        );

        // Start the main monitoring loop
        self.monitor_loop().await?;

        Ok(())
    }

    /// Stop the Port Guard daemon
    pub async fn stop(&self) -> Result<()> {
        {
            let mut running = self.is_running.lock().await;
            *running = false;
        }

        // Save reservations before stopping
        self.save_reservations().await?;

        info!("🛡️  Port Guard daemon stopped");
        Ok(())
    }

    /// Main monitoring loop
    async fn monitor_loop(&self) -> Result<()> {
        while *self.is_running.lock().await {
            // Check for port conflicts every 2 seconds
            if let Err(e) = self.check_port_conflicts().await {
                warn!("Error checking port conflicts: {}", e);
            }

            // Check for dead processes and restart them if auto-restart is enabled
            if self.auto_restart {
                if let Err(e) = self.check_and_restart_dead_processes().await {
                    warn!("Error checking/restarting dead processes: {}", e);
                }
            }

            // Clean up expired reservations
            if let Err(e) = self.cleanup_expired_reservations().await {
                warn!("Error cleaning up expired reservations: {}", e);
            }

            // Sleep for 2 seconds
            sleep(TokioDuration::from_secs(2)).await;
        }
        Ok(())
    }

    /// Check for port conflicts and resolve them
    async fn check_port_conflicts(&self) -> Result<()> {
        let mut monitor = self.process_monitor.lock().await;
        let processes = monitor.scan_processes().await?;

        // Group processes by port
        let mut port_processes: HashMap<u16, Vec<&ProcessInfo>> = HashMap::new();
        for process in processes.values() {
            if self.watched_ports.contains(&process.port) {
                port_processes
                    .entry(process.port)
                    .or_insert_with(Vec::new)
                    .push(process);
            }
        }

        self.enforce_allowed_processes(&port_processes).await?;

        // Check for conflicts
        for (port, processes) in port_processes {
            let allowed_processes: Vec<&ProcessInfo> = match self.allowed_process_name.as_deref() {
                Some(allowed_name) => processes
                    .into_iter()
                    .filter(|process| process.name == allowed_name)
                    .collect(),
                None => processes,
            };

            if allowed_processes.len() > 1 {
                // Multiple processes on the same port - this is a conflict
                let conflict = PortConflict {
                    port,
                    existing_process: allowed_processes[0].clone(),
                    new_process: allowed_processes[1].clone(),
                    conflict_type: PortConflictType::PortInUse,
                    resolution: None,
                };

                info!(
                    "⚠️  Port conflict detected on port {}: {} vs {}",
                    port, conflict.existing_process.name, conflict.new_process.name
                );

                // Resolve the conflict
                if let Err(e) = self.resolve_conflict(conflict).await {
                    warn!("Failed to resolve port conflict: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Check for dead processes and restart them
    async fn check_and_restart_dead_processes(&self) -> Result<()> {
        let reservations = self.reservations.lock().await;
        let mut monitor = self.process_monitor.lock().await;
        
        // Get currently running processes
        let processes = monitor.scan_processes().await?;
        
        // Collect all ports that need restarting (similar to cleanup_expired_reservations pattern)
        let mut ports_to_restart = Vec::new();
        
        for (port, reservation) in reservations.iter() {
            if !self.watched_ports.contains(port) {
                continue;
            }
            
            // Check if this port has a running process
            let has_process = processes.contains_key(port);
            
            if !has_process {
                // Port is free but should have a process - check if we can restart it
                let restart_manager = monitor.get_restart_manager();
                
                if restart_manager.can_restart(*port) {
                    ports_to_restart.push((*port, reservation.project_name.clone()));
                }
            }
        }
        
        // Drop locks before restarting to avoid deadlock
        drop(monitor);
        drop(reservations);
        
        // Restart all dead processes
        for (port, project_name) in ports_to_restart {
            info!(
                "🔄 Detected dead process on port {} (reserved for {}), restarting...",
                port, project_name
            );
            
            let mut monitor_mut = self.process_monitor.lock().await;
            if let Err(e) = monitor_mut.restart_process_on_port(port).await {
                warn!("Failed to auto-restart process on port {}: {}", port, e);
            } else {
                info!("✅ Successfully auto-restarted process on port {}", port);
            }
        }
        
        Ok(())
    }

    /// Resolve a port conflict
    async fn resolve_conflict(&self, mut conflict: PortConflict) -> Result<()> {
        if !self.auto_resolve {
            conflict.resolution = Some(PortResolution::NotifyUser);
            info!(
                "🔔 Port conflict on {} - manual resolution required",
                conflict.port
            );
            return Ok(());
        }

        // Auto-resolve by killing the older process
        let older_process = if self
            .is_process_older(&conflict.existing_process, &conflict.new_process)
            .await
        {
            &conflict.existing_process
        } else {
            &conflict.new_process
        };

        info!(
            "🔧 Auto-resolving port conflict on {} by killing process {} (PID: {})",
            conflict.port, older_process.name, older_process.pid
        );

        // Kill the older process
        if let Err(e) = self.kill_process(older_process.pid).await {
            warn!("Failed to kill process {}: {}", older_process.pid, e);
            return Err(e);
        }

        // Update conflict resolution
        conflict.resolution = Some(PortResolution::KillExisting);

        // Increment conflicts resolved counter
        {
            let mut count = self.conflicts_resolved.lock().await;
            *count += 1;
        }

        info!("✅ Port conflict resolved on port {}", conflict.port);
        Ok(())
    }

    /// Reserve a port for a specific project
    pub async fn reserve_port(
        &self,
        port: u16,
        project_name: String,
        process_name: String,
    ) -> Result<()> {
        let project_name_clone = project_name.clone();
        let reservation = PortReservation {
            port,
            project_name,
            process_name,
            reserved_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::hours(24)), // 24 hour reservation
            auto_renew: true,
        };

        {
            let mut reservations = self.reservations.lock().await;
            reservations.insert(port, reservation);
        }

        info!(
            "🔒 Port {} reserved for project '{}'",
            port, project_name_clone
        );
        self.save_reservations().await?;
        Ok(())
    }

    /// Release a port reservation
    pub async fn release_port(&self, port: u16) -> Result<()> {
        {
            let mut reservations = self.reservations.lock().await;
            reservations.remove(&port);
        }

        info!("🔓 Port {} reservation released", port);
        self.save_reservations().await?;
        Ok(())
    }

    /// Get current guard status
    pub async fn get_status(&self) -> GuardStatus {
        let reservations = self.reservations.lock().await;
        let conflicts_resolved = *self.conflicts_resolved.lock().await;
        let is_running = *self.is_running.lock().await;

        GuardStatus {
            is_active: is_running,
            watched_ports: self.watched_ports.clone(),
            active_reservations: reservations.values().cloned().collect(),
            conflicts_resolved,
            last_activity: Some(Utc::now()),
            auto_resolve_enabled: self.auto_resolve,
        }
    }

    /// Load reservations from file
    async fn load_reservations(&self) -> Result<()> {
        if !Path::new(&self.reservation_file).exists() {
            return Ok(());
        }

        let content = fs::read_to_string(&self.reservation_file)?;
        let reservations: HashMap<u16, PortReservation> = serde_json::from_str(&content)?;

        {
            let mut current_reservations = self.reservations.lock().await;
            *current_reservations = reservations;
        }

        info!(
            "📂 Loaded {} port reservations",
            self.reservations.lock().await.len()
        );
        Ok(())
    }

    /// Save reservations to file
    async fn save_reservations(&self) -> Result<()> {
        // Create directory if it doesn't exist
        if let Some(parent) = Path::new(&self.reservation_file).parent() {
            fs::create_dir_all(parent)?;
        }

        let reservations = self.reservations.lock().await;
        let content = serde_json::to_string_pretty(&*reservations)?;
        fs::write(&self.reservation_file, content)?;

        Ok(())
    }

    /// Clean up expired reservations
    async fn cleanup_expired_reservations(&self) -> Result<()> {
        let now = Utc::now();
        let mut reservations = self.reservations.lock().await;
        let mut to_remove = Vec::new();

        for (port, reservation) in reservations.iter() {
            if let Some(expires_at) = reservation.expires_at {
                if now > expires_at {
                    to_remove.push(*port);
                }
            }
        }

        for port in to_remove {
            reservations.remove(&port);
            info!("🧹 Cleaned up expired reservation for port {}", port);
        }

        Ok(())
    }

    /// Kill a process by PID
    async fn kill_process(&self, pid: i32) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            let output = Command::new("kill")
                .arg("-TERM")
                .arg(pid.to_string())
                .output()?;

            if !output.status.success() {
                // Try SIGKILL if SIGTERM fails
                let output = Command::new("kill")
                    .arg("-KILL")
                    .arg(pid.to_string())
                    .output()?;

                if !output.status.success() {
                    return Err(anyhow::anyhow!("Failed to kill process {}", pid));
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            use std::process::Command;
            let output = Command::new("kill")
                .arg("-TERM")
                .arg(pid.to_string())
                .output()?;

            if !output.status.success() {
                // Try SIGKILL if SIGTERM fails
                let output = Command::new("kill")
                    .arg("-KILL")
                    .arg(pid.to_string())
                    .output()?;

                if !output.status.success() {
                    return Err(anyhow::anyhow!("Failed to kill process {}", pid));
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            let output = Command::new("taskkill")
                .arg("/PID")
                .arg(pid.to_string())
                .arg("/F")
                .output()?;

            if !output.status.success() {
                return Err(anyhow::anyhow!("Failed to kill process {}", pid));
            }
        }

        Ok(())
    }

    /// Intercept a command and check for port conflicts before execution
    pub async fn intercept_command(&self, command: &str, args: &[String]) -> Result<()> {
        if !self.process_interception_enabled {
            return Ok(());
        }

        // Check if this is a development server command
        if self.is_development_server_command(command, args) {
            let target_port = self.extract_port_from_command(command, args);

            if let Some(port) = target_port {
                if self.watched_ports.contains(&port) {
                    info!(
                        "🔍 Intercepting command: {} - checking port {}",
                        command, port
                    );

                    // Check if port is already in use
                    if !is_port_available(port).await {
                        info!("⚠️  Port {} is busy, attempting to resolve conflict", port);

                        if self.auto_resolve {
                            // Try to kill the conflicting process
                            if let Err(e) = self.resolve_port_conflict(port).await {
                                warn!("Failed to resolve port conflict: {}", e);
                                return Err(e);
                            }

                            info!("✅ Port {} conflict resolved, command can proceed", port);
                        } else {
                            return Err(anyhow::anyhow!(
                                "Port {} is busy and auto-resolve is disabled",
                                port
                            ));
                        }
                    } else {
                        info!("✅ Port {} is available, command can proceed", port);
                    }
                }
            }
        }

        // Track intercepted command
        {
            let mut commands = self.intercepted_commands.lock().await;
            commands.insert(format!("{} {}", command, args.join(" ")));
        }

        Ok(())
    }

    /// Check if a command is a development server
    fn is_development_server_command(&self, command: &str, args: &[String]) -> bool {
        let dev_commands = [
            "npm", "yarn", "pnpm", "node", "python", "python3", "ruby", "rails", "cargo", "go",
            "java", "mvn", "gradle",
        ];

        let dev_args = [
            "start",
            "dev",
            "serve",
            "run",
            "server",
            "http.server",
            "rails",
            "server",
            "runserver",
            "serve",
            "dev",
        ];

        // Check if command is a development tool
        let is_dev_command = dev_commands.iter().any(|&cmd| command.contains(cmd));

        // Check if args contain development server keywords
        let is_dev_args = args
            .iter()
            .any(|arg| dev_args.iter().any(|&dev_arg| arg.contains(dev_arg)));

        is_dev_command && is_dev_args
    }

    /// Extract port number from command arguments
    fn extract_port_from_command(&self, _command: &str, args: &[String]) -> Option<u16> {
        // Flags whose next argument is a port number
        const PORT_FLAGS: &[&str] = &["--port", "-p", "--listen", "-l"];

        let mut i = 0;
        while i < args.len() {
            let arg = &args[i];

            // Handle --port=3000 or -p=3000 or --listen=8080 or -l=8080
            for flag in PORT_FLAGS {
                let prefix = format!("{}=", flag);
                if arg.starts_with(&prefix) {
                    if let Some(port_str) = arg.split('=').nth(1) {
                        if let Ok(port) = port_str.parse::<u16>() {
                            return Some(port);
                        }
                    }
                }
            }

            // Handle --port 3000 or -p 3000 (flag followed by value as next arg)
            if PORT_FLAGS.contains(&arg.as_str()) {
                if let Some(next_arg) = args.get(i + 1) {
                    if let Ok(port) = next_arg.parse::<u16>() {
                        return Some(port);
                    }
                }
            }

            i += 1;
        }

        None
    }

    /// Resolve port conflict by killing the conflicting process
    async fn resolve_port_conflict(&self, port: u16) -> Result<()> {
        let mut monitor = self.process_monitor.lock().await;
        let processes = monitor.scan_processes().await?;

        // Find processes using the port
        let conflicting_processes: Vec<&ProcessInfo> =
            processes.values().filter(|p| p.port == port).collect();

        if !conflicting_processes.is_empty() {
            let process_to_kill = match self.allowed_process_name.as_deref() {
                Some(allowed_name) => conflicting_processes
                    .iter()
                    .copied()
                    .find(|process| process.name != allowed_name)
                    .unwrap_or(conflicting_processes[0]),
                None => conflicting_processes[0],
            };
            info!(
                "🔧 Killing conflicting process {} (PID: {}) on port {}",
                process_to_kill.name, process_to_kill.pid, port
            );

            self.kill_process(process_to_kill.pid).await?;

            // Wait a moment for the process to die
            sleep(TokioDuration::from_millis(500)).await;

            // Verify port is now available
            if is_port_available(port).await {
                info!("✅ Port {} is now available", port);
                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "Port {} is still busy after killing process",
                    port
                ))
            }
        } else {
            Err(anyhow::anyhow!(
                "No conflicting process found on port {}",
                port
            ))
        }
    }

    async fn is_process_older(&self, first: &ProcessInfo, second: &ProcessInfo) -> bool {
        let (first_start, second_start) = {
            let mut monitor = self.process_monitor.lock().await;
            (
                monitor.get_process_start_time(first.pid),
                monitor.get_process_start_time(second.pid),
            )
        };

        match (first_start, second_start) {
            (Some(first_time), Some(second_time)) => first_time <= second_time,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => {
                warn!(
                    "Failed to determine process start times for PIDs {} and {}; falling back to PID comparison",
                    first.pid, second.pid
                );
                first.pid < second.pid
            }
        }
    }

    async fn enforce_allowed_processes(
        &self,
        port_processes: &HashMap<u16, Vec<&ProcessInfo>>,
    ) -> Result<()> {
        let allowed_name = match self.allowed_process_name.as_deref() {
            Some(name) => name,
            None => return Ok(()),
        };

        let mut disallowed_processes = Vec::new();
        for (port, processes) in port_processes {
            for process in processes {
                if process.name != allowed_name {
                    disallowed_processes.push((*port, process.pid, process.name.clone()));
                }
            }
        }

        if disallowed_processes.is_empty() {
            return Ok(());
        }

        for (port, pid, name) in disallowed_processes {
            if !self.auto_resolve {
                info!(
                    "🔔 Unauthorized process '{}' on port {} - manual resolution required",
                    name, port
                );
                continue;
            }

            info!(
                "🚨 Unauthorized process '{}' (PID: {}) on port {} - KILLING",
                name, pid, port
            );

            if let Err(e) = self.kill_process(pid).await {
                warn!("Failed to kill unauthorized process {}: {}", pid, e);
            }
        }

        Ok(())
    }

    /// Get intercepted commands count
    pub async fn get_intercepted_commands_count(&self) -> usize {
        let commands = self.intercepted_commands.lock().await;
        commands.len()
    }

    /// Enable/disable process interception
    pub fn set_process_interception(&mut self, enabled: bool) {
        self.process_interception_enabled = enabled;
    }
}

/// Check if a port is available for binding
pub async fn is_port_available(port: u16) -> bool {
    use std::net::Ipv4Addr;
    use std::net::{SocketAddr, TcpListener};

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    match TcpListener::bind(addr) {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Find an available port starting from a given port
pub async fn find_available_port(start_port: u16, max_attempts: u16) -> Option<u16> {
    for port in start_port..start_port + max_attempts {
        if is_port_available(port).await {
            return Some(port);
        }
    }
    None
}
