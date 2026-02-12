use crate::{
    cli::Args,
    endpoint_monitor::EndpointMonitor,
    port_guard::PortGuardDaemon,
    process_monitor::ProcessMonitor,
    security_audit::SecurityAuditor,
    smart_filter::SmartFilter,
    types::{GuardStatus, ProcessUpdate, SecurityAuditResult, StatusBarInfo},
};
use anyhow::Result;
use crossbeam_channel::{bounded, Receiver};
use log::{error, info};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct ConsolePortKillApp {
    process_monitor: Arc<Mutex<ProcessMonitor>>,
    update_receiver: Receiver<ProcessUpdate>,
    args: Args,
    port_guard: Option<Arc<PortGuardDaemon>>,
}

impl ConsolePortKillApp {
    /// Get a reference to the process monitor
    pub fn process_monitor(&self) -> Arc<Mutex<ProcessMonitor>> {
        self.process_monitor.clone()
    }

    /// Get a reference to the args
    pub fn args(&self) -> &Args {
        &self.args
    }

    pub fn new(args: Args) -> Result<Self> {
        // Create channels for communication
        let (update_sender, update_receiver) = bounded(100);

        // Create smart filter if needed
        let smart_filter = Self::create_smart_filter(&args)?;

        // Create process monitor with configurable ports
        println!(
            "DEBUG: Creating ProcessMonitor with verbose={}, performance={}",
            args.verbose, args.performance
        );
        let process_monitor = if let Some(filter) = smart_filter {
            Arc::new(Mutex::new(ProcessMonitor::new_with_performance(
                update_sender,
                args.get_ports_to_monitor(),
                args.docker,
                args.verbose,
                Some(filter),
                args.performance,
            )?))
        } else {
            Arc::new(Mutex::new(ProcessMonitor::new_with_performance(
                update_sender,
                args.get_ports_to_monitor(),
                args.docker,
                args.verbose,
                None,
                args.performance,
            )?))
        };

        // Initialize Port Guard if enabled
        let port_guard = if args.guard_mode {
            let guard_ports = args.get_guard_ports();
            let reservation_file = args.get_reservation_file_path();
            let mut daemon = PortGuardDaemon::new(
                guard_ports,
                reservation_file,
                args.auto_resolve,
                process_monitor.clone(),
            );
            daemon.set_process_interception(args.intercept_commands);
            daemon.set_auto_restart(args.guard_auto_restart);
            Some(Arc::new(daemon))
        } else {
            None
        };

        Ok(Self {
            process_monitor,
            update_receiver,
            args,
            port_guard,
        })
    }

    /// Get ports to scan, using smart defaults when no ports are specified
    fn get_ports_to_scan(args: &Args) -> Vec<u16> {
        args.get_ports_to_monitor()
    }

    /// Create a temporary process monitor with smart port selection
    async fn create_temp_monitor(&self, ports_to_scan: Vec<u16>) -> Result<ProcessMonitor> {
        let (update_sender, _update_receiver) = crossbeam_channel::bounded(100);
        let smart_filter = Self::create_smart_filter(&self.args)?;

        if let Some(filter) = smart_filter {
            ProcessMonitor::new_with_performance(
                update_sender,
                ports_to_scan,
                self.args.docker,
                self.args.verbose,
                Some(filter),
                self.args.performance,
            )
        } else {
            ProcessMonitor::new_with_performance(
                update_sender,
                ports_to_scan,
                self.args.docker,
                self.args.verbose,
                None,
                self.args.performance,
            )
        }
    }

    fn create_smart_filter(args: &Args) -> Result<Option<SmartFilter>> {
        // Get smart filter defaults
        let (smart_ignore_ports, smart_ignore_processes, smart_ignore_groups) =
            args.get_smart_filter_defaults();

        // Combine user ignores with smart ignores
        let mut ignore_ports = args.get_ignore_ports_set();
        ignore_ports.extend(smart_ignore_ports);

        let mut ignore_processes = args.get_ignore_processes_set();
        ignore_processes.extend(smart_ignore_processes);

        let mut ignore_groups = args.get_ignore_groups_set();
        ignore_groups.extend(smart_ignore_groups);

        // Check if any filtering is needed
        if ignore_ports.is_empty()
            && ignore_processes.is_empty()
            && args.ignore_patterns.is_none()
            && ignore_groups.is_empty()
            && args.only_groups.is_none()
        {
            return Ok(None);
        }

        let filter = SmartFilter::new(
            ignore_ports,
            ignore_processes,
            args.ignore_patterns.clone(),
            ignore_groups,
            args.get_only_groups_set(),
        )?;

        Ok(Some(filter))
    }

    pub async fn run(mut self) -> Result<()> {
        info!("Starting Console Port Kill application...");

        // One-shot: list current processes and exit
        if self.args.list {
            let ports_to_scan = Self::get_ports_to_scan(&self.args);
            let mut temp_monitor = self.create_temp_monitor(ports_to_scan).await?;
            let processes = temp_monitor.scan_processes().await?;
            if processes.is_empty() {
                println!("ℹ️  No processes detected");
            } else {
                println!("📋 Ports in use (one-time snapshot):");
                for (port, p) in &processes {
                    println!(
                        "  • Port {}: {} (PID {})",
                        port,
                        p.get_display_name(),
                        p.pid
                    );
                }
            }
            return Ok(());
        }

        // One-shot: clear specific port(s) provided as positional ports
        if !self.args.positional_ports.is_empty() {
            use crate::process_monitor::kill_all_processes as kill_on_ports;
            if self.args.safe {
                let ports_str = self
                    .args
                    .positional_ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                println!("Confirm kill on ports [{}]? y/N", ports_str);
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !matches!(input.trim(), "y" | "Y" | "yes" | "YES") {
                    println!("Cancelled.");
                    return Ok(());
                }
            }
            kill_on_ports(&self.args.positional_ports, &self.args)?;
            return Ok(());
        }

        // One-shot: --clear
        if let Some(port) = self.args.clear {
            if self.args.safe {
                println!("Confirm kill on port {}? y/N", port);
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !matches!(input.trim(), "y" | "Y" | "yes" | "YES") {
                    println!("Cancelled.");
                    return Ok(());
                }
            }
            use crate::process_monitor::kill_all_processes as kill_on_ports;
            kill_on_ports(&[port], &self.args)?;
            return Ok(());
        }

        // One-shot: --kill (by PID)
        if let Some(pid) = self.args.kill {
            if self.args.safe {
                println!("Confirm kill PID {}? y/N", pid);
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !matches!(input.trim(), "y" | "Y" | "yes" | "YES") {
                    println!("Cancelled.");
                    return Ok(());
                }
            }
            use crate::process_monitor::kill_single_process;
            kill_single_process(pid, &self.args)?;
            return Ok(());
        }

        // One-shot: file-based operations
        if let Some(path) = &self.args.kill_file {
            let fm = crate::file_monitor::FileMonitor::new();
            let procs = fm.find_processes_with_file(path)?;
            if procs.is_empty() {
                println!("ℹ️  No processes found holding {}", path);
                return Ok(());
            }
            if self.args.safe {
                println!(
                    "Confirm kill {} process(es) holding {}? y/N",
                    procs.len(),
                    path
                );
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !matches!(input.trim(), "y" | "Y" | "yes" | "YES") {
                    println!("Cancelled.");
                    return Ok(());
                }
            }
            // Kill each PID
            let (update_sender, _update_receiver) = crossbeam_channel::bounded(100);
            let mut temp_monitor = ProcessMonitor::new_with_performance(
                update_sender,
                vec![],
                self.args.docker,
                self.args.verbose,
                None,
                self.args.performance,
            )?;
            for p in procs {
                let _ = temp_monitor.kill_process(p.pid).await;
            }
            return Ok(());
        }

        if let Some(ext) = &self.args.kill_ext {
            let fm = crate::file_monitor::FileMonitor::new();
            let procs = fm.find_processes_with_extension(ext)?;
            if procs.is_empty() {
                println!("ℹ️  No processes found holding files with '{}'", ext);
                return Ok(());
            }
            if self.args.safe {
                println!(
                    "Confirm kill {} process(es) with files '{}'? y/N",
                    procs.len(),
                    ext
                );
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !matches!(input.trim(), "y" | "Y" | "yes" | "YES") {
                    println!("Cancelled.");
                    return Ok(());
                }
            }
            let (update_sender, _update_receiver) = crossbeam_channel::bounded(100);
            let mut temp_monitor = ProcessMonitor::new_with_performance(
                update_sender,
                vec![],
                self.args.docker,
                self.args.verbose,
                None,
                self.args.performance,
            )?;
            for p in procs {
                let _ = temp_monitor.kill_process(p.pid).await;
            }
            return Ok(());
        }

        if let Some(pattern) = &self.args.list_file {
            let fm = crate::file_monitor::FileMonitor::new();
            let procs = fm.find_processes_with_pattern(pattern)?;
            if procs.is_empty() {
                println!("ℹ️  No processes found matching file pattern '{}'", pattern);
            } else {
                println!("📋 Processes with matching files:");
                for p in procs {
                    println!("  • {} (PID {})", p.name, p.pid);
                }
            }
            return Ok(());
        }

        // Guard alias: --guard [--allow]
        if let Some(port) = self.args.guard {
            // Create a guard daemon on the single port
            let guard_ports = vec![port];
            let reservation_file = self.args.get_reservation_file_path();
            let mut daemon = PortGuardDaemon::new(
                guard_ports,
                reservation_file,
                true, // auto_resolve for alias to match guardPort intent
                self.process_monitor.clone(),
            );
            if let Some(name) = &self.args.allow {
                daemon.set_allowed_process_name(name.clone());
            }
            daemon.set_process_interception(self.args.intercept_commands);
            let guard = Arc::new(daemon);
            self.port_guard = Some(guard.clone());
            guard.start().await?;
            println!("🛡️  Guarding port {}. Press Ctrl+C to stop.", port);
            // Fall through to normal loop so the app stays running
        }

        if self.args.json {
            // JSON mode - output processes once and exit
            return self.output_processes_json().await;
        }

        // Check if endpoint monitoring is enabled
        if self.args.monitor_endpoint.is_some() {
            return self.run_endpoint_monitoring().await;
        }

        println!("🚀 Port Kill Console Monitor Started!");
        println!(
            "📡 Monitoring {} every 2 seconds...",
            self.args.get_port_description()
        );

        // Show filter information if filtering is enabled
        if let Ok(monitor) = self.process_monitor.try_lock() {
            if let Some(filter_stats) = monitor.get_filter_stats() {
                println!("🔍 {}", filter_stats.get_description());
            }
        }

        println!("💡 Press Ctrl+C to quit");
        println!("");

        // Start process monitoring in background
        let monitor = self.process_monitor.clone();
        tokio::spawn(async move {
            if let Err(e) = monitor.lock().await.start_monitoring().await {
                error!("Process monitoring failed: {}", e);
            }
        });

        // Handle updates in the main thread
        self.handle_console_updates().await;

        Ok(())
    }

    /// Run endpoint monitoring mode
    async fn run_endpoint_monitoring(&mut self) -> Result<()> {
        println!("🚀 Port Kill Endpoint Monitor Started!");
        println!(
            "📡 Monitoring {} every {}s, sending to endpoint every {}s",
            self.args.get_port_description(),
            self.args.scan_interval,
            self.args.send_interval
        );

        if let Some(ref endpoint) = self.args.monitor_endpoint {
            println!("🌐 Endpoint: {}", endpoint);
        }

        if self.args.endpoint_include_audit {
            println!("🔒 Security audit enabled");
        }

        println!("💡 Press Ctrl+C to quit");
        println!("");

        // Create endpoint monitor
        let mut endpoint_monitor = EndpointMonitor::new(&self.args)?;

        // Run the endpoint monitor
        endpoint_monitor.run(&self.args).await?;

        Ok(())
    }

    async fn output_processes_json(&mut self) -> Result<()> {
        // Use smart port selection to avoid hanging on large port ranges
        let ports_to_scan = Self::get_ports_to_scan(&self.args);
        let mut temp_monitor = self.create_temp_monitor(ports_to_scan).await?;
        let processes = temp_monitor.scan_processes().await?;

        // Filter out ignored processes
        let filtered_processes = self.filter_ignored_processes(&processes);

        // Output each process as JSON
        for (_port, process_info) in &filtered_processes {
            let json = serde_json::to_string(process_info)?;
            println!("{}", json);
        }

        Ok(())
    }

    async fn handle_console_updates(&mut self) {
        info!("Starting console update handler...");

        loop {
            // Check for process updates
            if let Ok(update) = self.update_receiver.try_recv() {
                // Filter out ignored processes
                let filtered_processes = self.filter_ignored_processes(&update.processes);
                let filtered_count = filtered_processes.len();

                // Update status
                let status_info = StatusBarInfo::from_processes_with_status(&filtered_processes);

                // Print status to console
                println!(
                    "🔄 Port Status: {} - {}",
                    status_info.text, status_info.tooltip
                );

                if filtered_count > 0 {
                    println!("📋 Detected Processes (after filtering ignored):");

                    // Show process summary
                    let mut group_counts: std::collections::HashMap<String, usize> =
                        std::collections::HashMap::new();
                    let mut project_counts: std::collections::HashMap<String, usize> =
                        std::collections::HashMap::new();

                    for (_, process_info) in &filtered_processes {
                        if let Some(ref group) = process_info.process_group {
                            *group_counts.entry(group.clone()).or_insert(0) += 1;
                        }
                        if let Some(ref project) = process_info.project_name {
                            *project_counts.entry(project.clone()).or_insert(0) += 1;
                        }
                    }

                    if !group_counts.is_empty() {
                        let group_summary: Vec<String> = group_counts
                            .iter()
                            .map(|(group, count)| format!("{}: {}", group, count))
                            .collect();
                        println!("   📊 Groups: {}", group_summary.join(", "));
                    }

                    if !project_counts.is_empty() {
                        let project_summary: Vec<String> = project_counts
                            .iter()
                            .map(|(project, count)| format!("{}: {}", project, count))
                            .collect();
                        println!("   📁 Projects: {}", project_summary.join(", "));
                    }

                    println!();

                    for (_port, process_info) in &filtered_processes {
                        if self.args.verbose {
                            // Verbose mode: show detailed description
                            let mut parts =
                                vec![format!("   • {}", process_info.get_detailed_description())];

                            // Add project context if requested
                            if self.args.show_context {
                                parts.push(format!(
                                    "[Context: {}]",
                                    process_info.get_project_description()
                                ));
                            }

                            // Add performance metrics if available
                            if self.args.performance {
                                if let Some(cpu) = process_info.cpu_usage {
                                    let cpu_indicator = if cpu > 50.0 {
                                        "🔥"
                                    } else if cpu > 20.0 {
                                        "⚠️"
                                    } else {
                                        "✅"
                                    };
                                    parts.push(format!("CPU: {:.1}%{}", cpu, cpu_indicator));
                                }
                                if let Some(memory) = process_info.memory_usage {
                                    let memory_mb = memory as f64 / 1024.0 / 1024.0;
                                    let memory_indicator = if memory_mb > 500.0 {
                                        "🔥"
                                    } else if memory_mb > 100.0 {
                                        "⚠️"
                                    } else {
                                        "✅"
                                    };
                                    parts.push(format!(
                                        "RAM: {:.1}MB{}",
                                        memory_mb, memory_indicator
                                    ));
                                }
                            }

                            if self.args.show_pid {
                                parts.push(format!("(PID {})", process_info.pid));
                            }

                            println!("{}", parts.join(" "));
                        } else {
                            // Normal mode: show enhanced display name
                            let mut parts = vec![format!(
                                "   • Port {}: {}",
                                _port,
                                process_info.get_display_name()
                            )];

                            // Add project context if requested
                            if self.args.show_context {
                                parts.push(format!(
                                    "[Context: {}]",
                                    process_info.get_project_description()
                                ));
                            }

                            // Add performance metrics if available
                            if self.args.performance {
                                if let Some(cpu) = process_info.cpu_usage {
                                    let cpu_indicator = if cpu > 50.0 {
                                        "🔥"
                                    } else if cpu > 20.0 {
                                        "⚠️"
                                    } else {
                                        "✅"
                                    };
                                    parts.push(format!("CPU: {:.1}%{}", cpu, cpu_indicator));
                                }
                                if let Some(memory) = process_info.memory_usage {
                                    let memory_mb = memory as f64 / 1024.0 / 1024.0;
                                    let memory_indicator = if memory_mb > 500.0 {
                                        "🔥"
                                    } else if memory_mb > 100.0 {
                                        "⚠️"
                                    } else {
                                        "✅"
                                    };
                                    parts.push(format!(
                                        "RAM: {:.1}MB{}",
                                        memory_mb, memory_indicator
                                    ));
                                }
                            }

                            if self.args.show_pid {
                                parts.push(format!("(PID {})", process_info.pid));
                            }

                            println!("{}", parts.join(" "));
                        }
                    }
                }

                // Show ignored processes if any
                let ignored_count = update.processes.len() - filtered_count;
                if ignored_count > 0 {
                    println!(
                        "🚫 Ignored {} process(es) based on user configuration",
                        ignored_count
                    );
                }

                println!("");
            }

            // Sleep briefly to avoid busy waiting
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    fn filter_ignored_processes(
        &self,
        processes: &HashMap<u16, crate::types::ProcessInfo>,
    ) -> HashMap<u16, crate::types::ProcessInfo> {
        let mut filtered = HashMap::new();

        // Get ignore sets for efficient lookup
        let ignore_ports = self.args.get_ignore_ports_set();
        let ignore_processes = self.args.get_ignore_processes_set();

        for (port, process_info) in processes {
            // Check if this process should be ignored
            let should_ignore =
                ignore_ports.contains(port) || ignore_processes.contains(&process_info.name);

            if !should_ignore {
                filtered.insert(*port, process_info.clone());
            } else {
                info!("Console: Ignoring process {} (PID {}) on port {} (ignored by user configuration)", 
                      process_info.name, process_info.pid, port);
            }
        }

        filtered
    }

    pub async fn display_history(&self) -> Result<()> {
        let monitor = self.process_monitor.lock().await;
        let history = monitor.get_history();

        if history.is_empty() {
            if self.args.json {
                println!("[]");
            } else {
                println!("📋 No process kill history found");
            }
            return Ok(());
        }

        if self.args.json {
            // Output history as JSON
            let recent_entries = history.get_recent_entries(50); // Show last 50 entries for API

            for entry in recent_entries.iter() {
                let json = serde_json::to_string(entry)?;
                println!("{}", json);
            }
        } else {
            // Output history in human-readable format
            println!("📋 Process Kill History ({} entries):", history.len());
            println!("{}", "─".repeat(80));

            let recent_entries = history.get_recent_entries(20); // Show last 20 entries

            for (i, entry) in recent_entries.iter().enumerate() {
                let display_name = entry.get_display_name();
                let time_str = format_time_ago(entry.killed_at);

                println!(
                    "{:2}. {} (PID {}) on port {} - {} ago",
                    i + 1,
                    display_name,
                    entry.pid,
                    entry.port,
                    time_str
                );

                if let Some(ref cmd_line) = entry.command_line {
                    println!("    Command: {}", cmd_line);
                }

                if let Some(ref work_dir) = entry.working_directory {
                    println!("    Directory: {}", work_dir);
                }

                println!("    Killed by: {}", entry.killed_by);
                println!();
            }
        }

        Ok(())
    }

    pub async fn clear_history(&self) -> Result<()> {
        let mut monitor = self.process_monitor.lock().await;
        monitor.clear_history();
        println!("🗑️  Process kill history cleared");
        Ok(())
    }

    pub async fn display_filter_info(&self) -> Result<()> {
        let monitor = self.process_monitor.lock().await;

        if let Some(filter_stats) = monitor.get_filter_stats() {
            println!("🔍 Filter Configuration:");
            println!("{}", "─".repeat(50));
            println!("{}", filter_stats.get_description());

            if filter_stats.ignore_ports_count > 0 {
                println!(
                    "  • Ignoring {} system ports",
                    filter_stats.ignore_ports_count
                );
            }
            if filter_stats.ignore_processes_count > 0 {
                println!(
                    "  • Ignoring {} system processes",
                    filter_stats.ignore_processes_count
                );
            }
            if filter_stats.ignore_patterns_count > 0 {
                println!(
                    "  • Using {} pattern filters",
                    filter_stats.ignore_patterns_count
                );
            }
            if filter_stats.ignore_groups_count > 0 {
                println!(
                    "  • Ignoring {} process groups",
                    filter_stats.ignore_groups_count
                );
            }
            if filter_stats.only_groups_count > 0 {
                println!(
                    "  • Showing only {} process groups",
                    filter_stats.only_groups_count
                );
            }
        } else {
            println!("🔍 No filtering enabled - showing all processes");
        }

        Ok(())
    }

    pub async fn kill_by_group(&self, groups: &[String]) -> Result<()> {
        // Use smart port selection to avoid hanging on large port ranges
        let ports_to_scan = Self::get_ports_to_scan(&self.args);
        let mut temp_monitor = self.create_temp_monitor(ports_to_scan).await?;
        let processes = temp_monitor.scan_processes().await?;

        let mut killed_count = 0;
        let mut total_count = 0;

        for (port, process_info) in &processes {
            if let Some(ref group) = process_info.process_group {
                if groups.contains(group) {
                    total_count += 1;
                    println!(
                        "🔪 Killing {} (PID {}) on port {} - Group: {}",
                        process_info.get_short_name(),
                        process_info.pid,
                        port,
                        group
                    );

                    if let Err(e) = temp_monitor.kill_process(process_info.pid).await {
                        println!(
                            "❌ Failed to kill {} (PID {}): {}",
                            process_info.get_short_name(),
                            process_info.pid,
                            e
                        );
                    } else {
                        killed_count += 1;
                    }
                }
            }
        }

        if total_count == 0 {
            println!("ℹ️  No processes found in groups: {}", groups.join(", "));
        } else {
            println!(
                "✅ Killed {}/{} processes from groups: {}",
                killed_count,
                total_count,
                groups.join(", ")
            );
        }

        Ok(())
    }

    pub async fn kill_by_project(&self, projects: &[String]) -> Result<()> {
        // Use smart port selection to avoid hanging on large port ranges
        let ports_to_scan = Self::get_ports_to_scan(&self.args);
        let mut temp_monitor = self.create_temp_monitor(ports_to_scan).await?;
        let processes = temp_monitor.scan_processes().await?;

        let mut killed_count = 0;
        let mut total_count = 0;

        for (port, process_info) in &processes {
            if let Some(ref project) = process_info.project_name {
                if projects.contains(project) {
                    total_count += 1;
                    println!(
                        "🔪 Killing {} (PID {}) on port {} - Project: {}",
                        process_info.get_short_name(),
                        process_info.pid,
                        port,
                        project
                    );

                    if let Err(e) = temp_monitor.kill_process(process_info.pid).await {
                        println!(
                            "❌ Failed to kill {} (PID {}): {}",
                            process_info.get_short_name(),
                            process_info.pid,
                            e
                        );
                    } else {
                        killed_count += 1;
                    }
                }
            }
        }

        if total_count == 0 {
            println!(
                "ℹ️  No processes found in projects: {}",
                projects.join(", ")
            );
        } else {
            println!(
                "✅ Killed {}/{} processes from projects: {}",
                killed_count,
                total_count,
                projects.join(", ")
            );
        }

        Ok(())
    }

    pub async fn kill_all_processes(&self) -> Result<()> {
        // Use smart port selection to avoid hanging on large port ranges
        let ports_to_scan = Self::get_ports_to_scan(&self.args);
        let mut temp_monitor = self.create_temp_monitor(ports_to_scan).await?;
        let processes = temp_monitor.scan_processes().await?;

        if processes.is_empty() {
            println!("ℹ️  No processes found to kill");
            return Ok(());
        }

        let total_count = processes.len();
        println!("🔪 Killing all {} processes...", total_count);

        // Use the ProcessMonitor's kill_all_processes method which handles history properly
        temp_monitor.kill_all_processes().await?;

        println!("✅ Killed all {} processes", total_count);

        Ok(())
    }

    pub async fn restart_processes(&self) -> Result<()> {
        // Use smart port selection to avoid hanging on large port ranges
        let ports_to_scan = Self::get_ports_to_scan(&self.args);
        let mut temp_monitor = self.create_temp_monitor(ports_to_scan).await?;
        let processes = temp_monitor.scan_processes().await?;

        if processes.is_empty() {
            println!("ℹ️  No processes to restart");
            return Ok(());
        }

        println!("🔄 Restarting {} processes...", processes.len());

        // Kill all processes
        for (port, process_info) in &processes {
            println!(
                "🔪 Killing {} (PID {}) on port {}",
                process_info.get_short_name(),
                process_info.pid,
                port
            );

            if let Err(e) = temp_monitor.kill_process(process_info.pid).await {
                println!(
                    "❌ Failed to kill {} (PID {}): {}",
                    process_info.get_short_name(),
                    process_info.pid,
                    e
                );
            }
        }

        println!("⏳ Waiting 3 seconds for processes to restart...");
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        // Check if processes have restarted
        let new_processes = temp_monitor.scan_processes().await?;
        if new_processes.is_empty() {
            println!("ℹ️  No processes detected after restart");
        } else {
            println!(
                "✅ Detected {} processes after restart",
                new_processes.len()
            );
        }

        Ok(())
    }

    pub async fn show_process_tree(&self) -> Result<()> {
        // Use smart port selection to avoid hanging on large port ranges
        let ports_to_scan = Self::get_ports_to_scan(&self.args);
        let mut temp_monitor = self.create_temp_monitor(ports_to_scan).await?;
        let processes = temp_monitor.scan_processes().await?;

        if processes.is_empty() {
            println!("ℹ️  No processes detected");
            return Ok(());
        }

        println!("🌳 Process Tree:");
        println!("{}", "─".repeat(60));

        // Group processes by project for better visualization
        let mut project_groups: std::collections::HashMap<String, Vec<_>> =
            std::collections::HashMap::new();

        for (port, process_info) in &processes {
            let project = process_info
                .project_name
                .as_ref()
                .map(|p| p.clone())
                .unwrap_or_else(|| "Unknown".to_string());
            project_groups
                .entry(project)
                .or_insert_with(Vec::new)
                .push((port, process_info));
        }

        for (project, project_processes) in &project_groups {
            println!("📁 Project: {}", project);
            for (port, process_info) in project_processes {
                let group_info = process_info
                    .process_group
                    .as_ref()
                    .map(|g| format!(" ({})", g))
                    .unwrap_or_default();

                println!(
                    "  ├─ Port {}: {}{} (PID {})",
                    port,
                    process_info.get_short_name(),
                    group_info,
                    process_info.pid
                );

                if let Some(ref work_dir) = process_info.working_directory {
                    println!("  │  └─ Working Directory: {}", work_dir);
                }

                if let (Some(_container_id), Some(container_name)) =
                    (&process_info.container_id, &process_info.container_name)
                {
                    println!("  │  └─ Docker Container: {}", container_name);
                }
            }
            println!();
        }

        Ok(())
    }

    pub async fn reset_development_ports(&self) -> Result<()> {
        let reset_ports = self.args.get_reset_ports();
        let port_list = reset_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        println!("🔄 Resetting common development ports: {}", port_list);
        println!("This will kill all processes on these ports:");
        for port in &reset_ports {
            println!("  • Port {} (common dev services)", port);
        }
        println!();

        // Use the existing kill_all_processes function directly with reset ports
        use crate::process_monitor::kill_all_processes;
        kill_all_processes(&reset_ports, &self.args)?;

        println!("✅ Reset complete! Development ports are now free and ready for use!");

        Ok(())
    }

    pub async fn show_frequent_offenders(&self) -> Result<()> {
        let monitor = self.process_monitor.lock().await;
        let history = monitor.get_history();

        if history.is_empty() {
            if self.args.json {
                println!("[]");
            } else {
                println!("ℹ️  No history available. Start killing some processes to see frequent offenders!");
            }
            return Ok(());
        }

        let offenders = history.get_frequent_offenders(2); // Show processes killed 2+ times

        if self.args.json {
            // Output JSON for API consumption
            for offender in &offenders {
                println!("{}", serde_json::to_string(offender)?);
            }
            return Ok(());
        }

        if offenders.is_empty() {
            println!("✅ No frequent offenders found! All processes have been killed only once.");
            return Ok(());
        }

        println!("🚨 Frequent Offenders (killed 2+ times):");
        println!("{}", "─".repeat(80));

        for (i, offender) in offenders.iter().enumerate() {
            let time_span = offender
                .last_killed
                .signed_duration_since(offender.first_killed);
            let time_span_str = if time_span.num_days() > 0 {
                format!("{}d", time_span.num_days())
            } else if time_span.num_hours() > 0 {
                format!("{}h", time_span.num_hours())
            } else {
                format!("{}m", time_span.num_minutes())
            };

            println!(
                "{}. {} on port {} (killed {} times over {})",
                i + 1,
                offender.process_name,
                offender.port,
                offender.kill_count,
                time_span_str
            );

            if let Some(ref group) = offender.process_group {
                println!("   Group: {}", group);
            }
            if let Some(ref project) = offender.project_name {
                println!("   Project: {}", project);
            }
            println!(
                "   First killed: {}",
                offender.first_killed.format("%Y-%m-%d %H:%M")
            );
            println!(
                "   Last killed: {}",
                offender.last_killed.format("%Y-%m-%d %H:%M")
            );
            println!();
        }

        println!("💡 Consider adding these to your ignore lists to avoid repeated kills!");

        Ok(())
    }

    pub async fn show_time_patterns(&self) -> Result<()> {
        let monitor = self.process_monitor.lock().await;
        let history = monitor.get_history();

        if history.is_empty() {
            println!(
                "ℹ️  No history available. Start killing some processes to see time patterns!"
            );
            return Ok(());
        }

        let patterns = history.get_time_patterns();

        println!("📊 Time Patterns Analysis:");
        println!("{}", "─".repeat(50));
        println!("Total kills: {}", patterns.total_kills);

        if let Some(peak_hour) = patterns.peak_hour {
            println!("Peak hour: {}:00", peak_hour);
        }

        if let Some(peak_day) = patterns.peak_day {
            println!("Peak day: {}", peak_day);
        }

        println!();
        println!("📈 Hour Distribution:");
        let mut hour_entries: Vec<_> = patterns.hour_distribution.iter().collect();
        hour_entries.sort_by_key(|(hour, _)| *hour);

        for (hour, count) in hour_entries {
            let bar_length = (*count as f32 / patterns.total_kills as f32 * 20.0) as usize;
            let bar = "█".repeat(bar_length);
            println!("{:2}:00 │{} {} kills", hour, bar, count);
        }

        println!();
        println!("📅 Day Distribution:");
        let day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
        for (day, count) in &patterns.day_distribution {
            let day_name = day_names[*day as usize];
            let bar_length = (*count as f32 / patterns.total_kills as f32 * 20.0) as usize;
            let bar = "█".repeat(bar_length);
            println!("{} │{} {} kills", day_name, bar, count);
        }

        Ok(())
    }

    pub async fn show_ignore_suggestions(&self) -> Result<()> {
        let monitor = self.process_monitor.lock().await;
        let history = monitor.get_history();

        if history.is_empty() {
            if self.args.json {
                println!("null");
            } else {
                println!(
                    "ℹ️  No history available. Start killing some processes to get suggestions!"
                );
            }
            return Ok(());
        }

        let suggestions = history.get_ignore_suggestions(2); // Suggest for processes killed 2+ times

        if self.args.json {
            // Output JSON for API consumption
            println!("{}", serde_json::to_string(&suggestions)?);
            return Ok(());
        }

        println!("💡 Auto-Suggestions for Ignore Lists:");
        println!("{}", "─".repeat(60));

        if !suggestions.suggested_ports.is_empty() {
            println!("🔌 Suggested Ports to Ignore:");
            for port in &suggestions.suggested_ports {
                println!("  --ignore-ports {}", port);
            }
            println!();
        }

        if !suggestions.suggested_processes.is_empty() {
            println!("⚙️  Suggested Process Names to Ignore:");
            for process in &suggestions.suggested_processes {
                println!("  --ignore-processes {}", process);
            }
            println!();
        }

        if !suggestions.suggested_groups.is_empty() {
            println!("📦 Suggested Groups to Ignore:");
            for group in &suggestions.suggested_groups {
                println!("  --ignore-groups {}", group);
            }
            println!();
        }

        if suggestions.suggested_ports.is_empty()
            && suggestions.suggested_processes.is_empty()
            && suggestions.suggested_groups.is_empty()
        {
            println!("✅ No suggestions! Your current ignore settings are working well.");
        } else {
            println!("📋 Complete Command Example:");
            let mut args = Vec::new();
            if !suggestions.suggested_ports.is_empty() {
                let ports = suggestions
                    .suggested_ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                args.push(format!("--ignore-ports {}", ports));
            }
            if !suggestions.suggested_processes.is_empty() {
                let processes = suggestions.suggested_processes.join(",");
                args.push(format!("--ignore-processes {}", processes));
            }
            if !suggestions.suggested_groups.is_empty() {
                let groups = suggestions.suggested_groups.join(",");
                args.push(format!("--ignore-groups {}", groups));
            }

            if !args.is_empty() {
                println!(
                    "./port-kill-console --console --ports 3000,8000 {}",
                    args.join(" ")
                );
            }
        }

        Ok(())
    }

    pub async fn show_history_statistics(&self) -> Result<()> {
        let monitor = self.process_monitor.lock().await;
        let history = monitor.get_history();

        if history.is_empty() {
            if self.args.json {
                println!("null");
            } else {
                println!(
                    "ℹ️  No history available. Start killing some processes to see statistics!"
                );
            }
            return Ok(());
        }

        let stats = history.get_statistics();

        if self.args.json {
            // Output JSON for API consumption
            println!("{}", serde_json::to_string(&stats)?);
            return Ok(());
        }

        println!("📊 History Statistics:");
        println!("{}", "─".repeat(50));
        println!("Total kills: {}", stats.total_kills);
        println!("Unique processes: {}", stats.unique_processes);
        println!("Unique ports: {}", stats.unique_ports);
        println!("Unique projects: {}", stats.unique_projects);
        println!("Average kills per day: {:.1}", stats.average_kills_per_day);

        if let Some((name, count)) = &stats.most_killed_process {
            println!("Most killed process: {} ({} times)", name, count);
        }

        if let Some((port, count)) = &stats.most_killed_port {
            println!("Most killed port: {} ({} times)", port, count);
        }

        if let Some((project, count)) = &stats.most_killed_project {
            println!("Most killed project: {} ({} times)", project, count);
        }

        if let Some(oldest) = &stats.oldest_kill {
            println!("Oldest kill: {}", oldest.format("%Y-%m-%d %H:%M"));
        }

        if let Some(newest) = &stats.newest_kill {
            println!("Newest kill: {}", newest.format("%Y-%m-%d %H:%M"));
        }

        Ok(())
    }

    pub async fn show_root_cause_analysis(&self) -> Result<()> {
        let monitor = self.process_monitor.lock().await;
        let history = monitor.get_history();

        if history.is_empty() {
            if self.args.json {
                println!("null");
            } else {
                println!("ℹ️  No history available. Start killing some processes to get root cause analysis!");
            }
            return Ok(());
        }

        let analysis = history.get_root_cause_analysis();

        if self.args.json {
            // Output JSON for API consumption
            println!("{}", serde_json::to_string(&analysis)?);
            return Ok(());
        }

        println!("🧠 Smart Root Cause Analysis:");
        println!("{}", "─".repeat(60));
        println!("{}", analysis.summary);
        println!();

        // Show conflicts
        if !analysis.conflicts.is_empty() {
            println!("⚠️  Detected Conflicts:");
            for (i, conflict) in analysis.conflicts.iter().enumerate() {
                println!(
                    "{}. Port {} - {} (Severity: {:?})",
                    i + 1,
                    conflict.port,
                    format!("{:?}", conflict.conflict_type).replace("ConflictType::", ""),
                    conflict.severity
                );
                println!(
                    "   Processes: {}",
                    conflict.conflicting_processes.join(", ")
                );
                println!("   Recommendation: {}", conflict.recommendation);
                println!();
            }
        }

        // Show patterns
        if !analysis.patterns.is_empty() {
            println!("📊 Workflow Patterns:");
            for (i, pattern) in analysis.patterns.iter().enumerate() {
                println!(
                    "{}. {} (Confidence: {:.0}%)",
                    i + 1,
                    pattern.description,
                    pattern.confidence * 100.0
                );
                println!("   Type: {:?}", pattern.pattern_type);
                println!("   Frequency: {}", pattern.frequency);
                println!("   Recommendation: {}", pattern.recommendation);
                println!();
            }
        }

        // Show recommendations
        if !analysis.recommendations.is_empty() {
            println!("💡 Smart Recommendations:");
            for (i, rec) in analysis.recommendations.iter().enumerate() {
                println!("{}. {} (Priority: {:?})", i + 1, rec.title, rec.priority);
                println!("   Category: {:?}", rec.category);
                println!("   Description: {}", rec.description);
                println!("   Action: {}", rec.action);
                println!("   Impact: {}", rec.impact);
                println!();
            }
        }

        if analysis.conflicts.is_empty()
            && analysis.patterns.is_empty()
            && analysis.recommendations.is_empty()
        {
            println!("✅ No issues detected! Your development workflow is running smoothly.");
        }

        Ok(())
    }

    /// Start Port Guard daemon
    pub async fn start_port_guard(&self) -> Result<()> {
        if let Some(guard) = &self.port_guard {
            guard.start().await?;
            info!("🛡️  Port Guard daemon started successfully");
        } else {
            return Err(anyhow::anyhow!("Port Guard mode not enabled"));
        }
        Ok(())
    }

    /// Stop Port Guard daemon
    pub async fn stop_port_guard(&self) -> Result<()> {
        if let Some(guard) = &self.port_guard {
            guard.stop().await?;
            info!("🛡️  Port Guard daemon stopped");
        } else {
            return Err(anyhow::anyhow!("Port Guard mode not enabled"));
        }
        Ok(())
    }

    /// Get Port Guard status
    pub async fn get_port_guard_status(&self) -> Result<GuardStatus> {
        if let Some(guard) = &self.port_guard {
            Ok(guard.get_status().await)
        } else {
            Err(anyhow::anyhow!("Port Guard mode not enabled"))
        }
    }

    /// Reserve a port
    pub async fn reserve_port(
        &self,
        port: u16,
        project_name: String,
        process_name: String,
    ) -> Result<()> {
        if let Some(guard) = &self.port_guard {
            guard.reserve_port(port, project_name, process_name).await?;
            info!("🔒 Port {} reserved", port);
        } else {
            return Err(anyhow::anyhow!("Port Guard mode not enabled"));
        }
        Ok(())
    }

    /// Release a port reservation
    pub async fn release_port(&self, port: u16) -> Result<()> {
        if let Some(guard) = &self.port_guard {
            guard.release_port(port).await?;
            info!("🔓 Port {} reservation released", port);
        } else {
            return Err(anyhow::anyhow!("Port Guard mode not enabled"));
        }
        Ok(())
    }

    /// Intercept a command for port conflict checking
    pub async fn intercept_command(&self, command: &str, args: &[String]) -> Result<()> {
        if let Some(guard) = &self.port_guard {
            guard.intercept_command(command, args).await?;
        } else {
            return Err(anyhow::anyhow!("Port Guard mode not enabled"));
        }
        Ok(())
    }

    /// Get intercepted commands count
    pub async fn get_intercepted_commands_count(&self) -> Result<usize> {
        if let Some(guard) = &self.port_guard {
            Ok(guard.get_intercepted_commands_count().await)
        } else {
            Err(anyhow::anyhow!("Port Guard mode not enabled"))
        }
    }

    /// Perform security audit
    pub async fn perform_security_audit(&self) -> Result<()> {
        // Use smart port selection to avoid hanging on large port ranges
        let ports_to_scan = Self::get_ports_to_scan(&self.args);
        let mut temp_monitor = self.create_temp_monitor(ports_to_scan).await?;
        let processes = temp_monitor.scan_processes().await?;

        // Limit audit to only processes that are actually running
        // This prevents hanging when scanning large port ranges
        if processes.is_empty() {
            println!("ℹ️  No processes found to audit");
            return Ok(());
        }

        info!(
            "🔒 Starting security audit on {} active processes",
            processes.len()
        );

        let auditor = SecurityAuditor::new(
            self.args.get_suspicious_ports(),
            self.args.get_baseline_file_path(),
            self.args.suspicious_only,
        );

        let audit_result = auditor.perform_audit(processes).await?;

        if self.args.json {
            // Output JSON for API consumption
            println!("{}", serde_json::to_string_pretty(&audit_result)?);
            return Ok(());
        }

        // Display audit results
        self.display_audit_results(&audit_result).await?;
        Ok(())
    }

    /// Execute command on remote host via SSH
    pub async fn execute_remote_command(&self, command: &str) -> Result<String> {
        if let Some(remote_host) = &self.args.get_remote_host() {
            let ssh_command = format!("ssh {} '{}'", remote_host, command);

            let output = std::process::Command::new("sh")
                .arg("-c")
                .arg(&ssh_command)
                .output()?;

            if output.status.success() {
                Ok(String::from_utf8_lossy(&output.stdout).to_string())
            } else {
                Err(anyhow::anyhow!(
                    "Remote command failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ))
            }
        } else {
            Err(anyhow::anyhow!("No remote host specified"))
        }
    }

    /// Run in remote mode - execute commands on remote host
    pub async fn run_remote_mode(&self, remote_host: &str) -> Result<()> {
        println!("🌐 Remote Mode: Connecting to {}", remote_host);

        // Build the remote command
        let mut remote_command = String::from("./port-kill-console");

        // Add console mode
        remote_command.push_str(" --console");

        // Add ports if specified
        if !self.args.get_ports_to_monitor().is_empty() {
            let ports_str = self
                .args
                .get_ports_to_monitor()
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",");
            remote_command.push_str(&format!(" --ports {}", ports_str));
        }

        // Add other flags
        if self.args.verbose {
            remote_command.push_str(" --verbose");
        }
        if self.args.docker {
            remote_command.push_str(" --docker");
        }
        if self.args.show_pid {
            remote_command.push_str(" --show-pid");
        }
        if self.args.json {
            remote_command.push_str(" --json");
        }

        println!("📡 Executing: {}", remote_command);

        // Execute the command on remote host
        let output = self.execute_remote_command(&remote_command).await?;

        // Display the output
        print!("{}", output);

        Ok(())
    }

    /// Display security audit results
    async fn display_audit_results(&self, result: &SecurityAuditResult) -> Result<()> {
        println!("🔒 SECURITY AUDIT RESULTS");
        println!("{}", "═".repeat(50));
        println!(
            "📊 Audit Timestamp: {}",
            result.audit_timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!("🔍 Total Ports Scanned: {}", result.total_ports_scanned);
        println!("🛡️  Security Score: {:.1}/100", result.security_score);
        println!();

        // Show suspicious processes
        if !result.suspicious_processes.is_empty() {
            println!("🚨 SUSPICIOUS ACTIVITY DETECTED:");
            for (i, suspicious) in result.suspicious_processes.iter().enumerate() {
                println!(
                    "{}. Port {}: {} (PID: {})",
                    i + 1,
                    suspicious.port,
                    suspicious.process_info.name,
                    suspicious.process_info.pid
                );
                println!("   Risk Level: {:?}", suspicious.risk_level);
                println!("   Reason: {:?}", suspicious.suspicion_reason);
                if let Some(hash) = &suspicious.binary_hash {
                    println!("   Binary Hash: {}", hash);
                }
                println!("   Network: {}", suspicious.network_interface);
                println!();
            }
        } else {
            println!("✅ No suspicious processes detected!");
        }

        // Show approved processes (if not suspicious_only mode)
        if !self.args.suspicious_only && !result.approved_processes.is_empty() {
            println!("✅ APPROVED SERVICES:");
            for approved in &result.approved_processes {
                println!(
                    "   Port {}: {} ({:?})",
                    approved.port, approved.process_info.name, approved.service_type
                );
            }
            println!();
        }

        // Show recommendations
        if !result.recommendations.is_empty() {
            println!("💡 SECURITY RECOMMENDATIONS:");
            for (i, rec) in result.recommendations.iter().enumerate() {
                println!("{}. {} (Priority: {:?})", i + 1, rec.title, rec.priority);
                println!("   {}", rec.description);
                println!("   Action: {}", rec.action);
                println!();
            }
        }

        // Show baseline comparison
        if let Some(baseline) = &result.baseline_comparison {
            println!("📋 BASELINE COMPARISON:");
            println!("   Baseline File: {}", baseline.baseline_file);
            println!("   New Processes: {}", baseline.new_processes.len());
            println!("   Removed Processes: {}", baseline.removed_processes.len());
            println!("   Changed Processes: {}", baseline.changed_processes.len());
            println!();
        }

        Ok(())
    }

    /// Restart a specific port using saved restart information
    pub async fn restart_port(&self, port: u16) -> Result<()> {
        println!("🔄 Restarting process on port {}...", port);

        let mut monitor = self.process_monitor.lock().await;
        
        // Check if we have restart info for this port
        if !monitor.get_restart_manager().can_restart(port) {
            println!("❌ No restart information available for port {}", port);
            println!("💡 Tip: Kill a process first to save its restart information");
            return Ok(());
        }

        // Show what we're going to restart
        if let Some(restart_info) = monitor.get_restart_manager().get_restart_info(port) {
            println!("   Command: {:?}", restart_info.command.join(" "));
            println!("   Working Directory: {}", restart_info.working_directory);
        }

        // Perform the restart
        match monitor.restart_process_on_port(port).await {
            Ok(()) => {
                println!("✅ Process on port {} restarted successfully", port);
            }
            Err(e) => {
                println!("❌ Failed to restart process on port {}: {}", port, e);
            }
        }

        Ok(())
    }

    /// Show restart history
    pub async fn show_restart_history(&self) -> Result<()> {
        let monitor = self.process_monitor.lock().await;
        let restart_manager = monitor.get_restart_manager();
        let restartable_ports = restart_manager.list_restartable_ports();

        if restartable_ports.is_empty() {
            println!("ℹ️  No processes available for restart");
            println!("💡 Tip: Kill processes with verbose mode (-v) to save restart information");
            return Ok(());
        }

        println!("📋 RESTART HISTORY");
        println!("   {} port(s) can be restarted:", restartable_ports.len());
        println!();

        for port in restartable_ports {
            if let Some(restart_info) = restart_manager.get_restart_info(port) {
                println!("   Port {}", port);
                println!("      Command: {}", restart_info.command.join(" "));
                println!("      Working Dir: {}", restart_info.working_directory);
                println!("      Last Restarted: {}", format_time_ago(restart_info.last_restarted));
                println!();
            }
        }

        println!("💡 Use --restart <port> to restart a specific port");
        
        Ok(())
    }

    /// Clear restart history for a specific port
    pub async fn clear_restart_history(&self, port: u16) -> Result<()> {
        let mut monitor = self.process_monitor.lock().await;
        let restart_manager = monitor.get_restart_manager_mut();
        
        match restart_manager.clear_port(port) {
            Ok(()) => {
                println!("✅ Cleared restart history for port {}", port);
            }
            Err(e) => {
                println!("❌ Failed to clear restart history: {}", e);
            }
        }

        Ok(())
    }

    /// Detect available services
    pub async fn detect_services(&self) -> Result<()> {
        use crate::service_detector::ServiceDetector;

        println!("🔍 Detecting available services...");
        println!();

        let detector = ServiceDetector::new();
        let services = detector.discover_services()?;

        if services.is_empty() {
            println!("ℹ️  No services detected in current directory");
            println!("💡 Tip: Run this command from a project directory containing:");
            println!("   • package.json (npm scripts)");
            println!("   • docker-compose.yml (Docker services)");
            println!("   • Procfile (Procfile processes)");
            println!("   • app.py/manage.py (Python apps)");
            return Ok(());
        }

        println!("📋 DETECTED SERVICES");
        println!("   Found {} service(s):", services.len());
        println!();

        for service in &services {
            println!("   {} - {}", service.name, service.description);
            if let Some(port) = service.inferred_port {
                println!("      Inferred Port: {}", port);
            }
            println!("      Working Dir: {}", service.working_directory.display());
            println!();
        }

        println!("💡 Use --start <name> to start a service (e.g., --start npm:dev)");

        Ok(())
    }

    /// Start a detected service
    pub async fn start_service(&self, service_name: &str) -> Result<()> {
        use crate::service_detector::ServiceDetector;

        println!("🚀 Starting service: {}...", service_name);

        let detector = ServiceDetector::new();
        let services = detector.discover_services()?;

        // Find the service
        let service = services.iter().find(|s| s.name == service_name);

        if service.is_none() {
            println!("❌ Service '{}' not found", service_name);
            println!("💡 Use --detect to list available services");
            return Ok(());
        }

        let service = service.unwrap();

        println!("   Starting: {}", service.description);
        if let Some(port) = service.inferred_port {
            println!("   Expected Port: {}", port);
        }
        println!();

        match detector.start_service(service) {
            Ok(pid) => {
                println!("✅ Service started successfully with PID {}", pid);
                println!("💡 The service is now running in the background");
            }
            Err(e) => {
                println!("❌ Failed to start service: {}", e);
            }
        }

        Ok(())
    }

    /// Initialize a sample configuration file
    pub async fn init_config(&self) -> Result<()> {
        use crate::orchestrator::create_sample_config;
        use std::path::Path;

        let config_path = Path::new(&self.args.config_file);

        if config_path.exists() {
            println!("❌ Configuration file already exists: {}", config_path.display());
            println!("💡 Delete it first or use a different --config-file path");
            return Ok(());
        }

        create_sample_config(config_path)?;
        println!("✅ Created sample configuration file: {}", config_path.display());
        println!();
        println!("📝 Edit the file to configure your services, then run:");
        println!("   port-kill --up     # Start all services");
        println!("   port-kill --down   # Stop all services");
        println!("   port-kill --status # Check service status");

        Ok(())
    }

    /// Start all services from config
    pub async fn orchestrate_up(&self) -> Result<()> {
        use crate::orchestrator::Orchestrator;
        use std::path::Path;

        let config_path = Path::new(&self.args.config_file);

        if !config_path.exists() {
            println!("❌ Configuration file not found: {}", config_path.display());
            println!("💡 Create one with: port-kill --init-config");
            return Ok(());
        }

        println!("🚀 Starting services from {}...", config_path.display());
        println!();

        let mut orchestrator = Orchestrator::load(config_path)?;

        match orchestrator.start_all().await {
            Ok(()) => {
                println!();
                println!("✅ All services started successfully!");
                println!();
                self.show_orchestrator_status(&orchestrator).await?;
            }
            Err(e) => {
                println!("❌ Failed to start services: {}", e);
                // Try to stop any services that were started
                let _ = orchestrator.stop_all().await;
            }
        }

        Ok(())
    }

    /// Stop all services from config
    pub async fn orchestrate_down(&self) -> Result<()> {
        use crate::orchestrator::Orchestrator;
        use std::path::Path;

        let config_path = Path::new(&self.args.config_file);

        if !config_path.exists() {
            println!("❌ Configuration file not found: {}", config_path.display());
            return Ok(());
        }

        println!("🛑 Stopping services from {}...", config_path.display());
        println!();

        let mut orchestrator = Orchestrator::load(config_path)?;

        match orchestrator.stop_all().await {
            Ok(()) => {
                println!("✅ All services stopped successfully!");
            }
            Err(e) => {
                println!("❌ Failed to stop services: {}", e);
            }
        }

        Ok(())
    }

    /// Restart a specific service from config
    pub async fn orchestrate_restart(&self, service_name: &str) -> Result<()> {
        use crate::orchestrator::Orchestrator;
        use std::path::Path;

        let config_path = Path::new(&self.args.config_file);

        if !config_path.exists() {
            println!("❌ Configuration file not found: {}", config_path.display());
            return Ok(());
        }

        println!("🔄 Restarting service '{}'...", service_name);

        let mut orchestrator = Orchestrator::load(config_path)?;

        match orchestrator.restart_service(service_name).await {
            Ok(()) => {
                println!("✅ Service '{}' restarted successfully!", service_name);
            }
            Err(e) => {
                println!("❌ Failed to restart service '{}': {}", service_name, e);
            }
        }

        Ok(())
    }

    /// Show status of all configured services
    pub async fn orchestrate_status(&self) -> Result<()> {
        use crate::orchestrator::Orchestrator;
        use std::path::Path;

        let config_path = Path::new(&self.args.config_file);

        if !config_path.exists() {
            println!("❌ Configuration file not found: {}", config_path.display());
            println!("💡 Create one with: port-kill --init-config");
            return Ok(());
        }

        let orchestrator = Orchestrator::load(config_path)?;

        self.show_orchestrator_status(&orchestrator).await?;

        Ok(())
    }

    /// Show orchestrator status (helper method)
    async fn show_orchestrator_status(&self, orchestrator: &crate::orchestrator::Orchestrator) -> Result<()> {
        let statuses = orchestrator.get_status();

        if statuses.is_empty() {
            println!("ℹ️  No services configured");
            return Ok(());
        }

        println!("📋 SERVICE STATUS");
        println!();

        for status in statuses {
            let status_icon = if status.running { "✅" } else { "⭕" };
            let status_text = if status.running { "RUNNING" } else { "STOPPED" };

            println!("   {} {} - {}", status_icon, status.name, status_text);
            println!("      Command: {}", status.command);

            if let Some(port) = status.port {
                println!("      Port: {}", port);
            }

            if let Some(pid) = status.pid {
                println!("      PID: {}", pid);
            }

            println!();
        }

        Ok(())
    }
}

fn format_time_ago(time: chrono::DateTime<chrono::Utc>) -> String {
    let now = chrono::Utc::now();
    let duration = now.signed_duration_since(time);

    let seconds = duration.num_seconds();
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else if seconds < 86400 {
        format!("{}h {}m", seconds / 3600, (seconds % 3600) / 60)
    } else {
        format!("{}d {}h", seconds / 86400, (seconds % 86400) / 3600)
    }
}
