use crate::{cli::Args, tray_menu::TrayMenu, types::{ProcessInfo, StatusBarInfo}};
use anyhow::Result;
use crossbeam_channel::{bounded, Receiver};
use log::{error, info, warn};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
#[cfg(target_os = "macos")]
use tray_icon::{menu::MenuEvent, TrayIcon, TrayIconBuilder};
#[cfg(target_os = "macos")]
use winit::event_loop::EventLoop;

#[cfg(target_os = "macos")]
pub struct PortKillApp {
    tray_icon: Arc<StdMutex<Option<TrayIcon>>>,
    menu_event_receiver: Receiver<MenuEvent>,
    tray_menu: TrayMenu,
    args: Args,
    current_processes: Arc<StdMutex<HashMap<u16, crate::types::ProcessInfo>>>,
    menu_id_to_port: Arc<StdMutex<HashMap<String, u16>>>,
}

#[cfg(target_os = "macos")]
impl PortKillApp {
    pub fn new(args: Args) -> Result<Self> {
        // Create channels for communication
        let (menu_sender, menu_event_receiver) = bounded(100);

        // Create tray menu
        let tray_menu = TrayMenu::new(menu_sender)?;

        Ok(Self {
            tray_icon: Arc::new(StdMutex::new(None)),
            menu_event_receiver,
            tray_menu,
            args,
            current_processes: Arc::new(StdMutex::new(HashMap::new())),
            menu_id_to_port: Arc::new(StdMutex::new(HashMap::new())),
        })
    }

    pub fn run(self) -> Result<()> {
        info!("Starting Port Kill application...");

        // Create event loop first (before any NSApplication initialization)
        let event_loop = EventLoop::new()?;

        // Now create the tray icon after the event loop is created
        info!("Creating tray icon...");
        let initial_menu = self.tray_menu.get_current_menu()?;
        let tray_icon = TrayIconBuilder::new()
            .with_tooltip("Port Kill - Development Port Monitor (Click or press Cmd+Shift+P)")
            .with_menu(Box::new(initial_menu))
            .with_icon(self.tray_menu.icon.clone())
            .build()?;

        info!("Tray icon created successfully!");

        // Store the tray icon
        if let Ok(mut tray_icon_guard) = self.tray_icon.lock() {
            *tray_icon_guard = Some(tray_icon);
        }

        // For now, let's manually check for processes every 5 seconds in the event loop
        let tray_icon = self.tray_icon.clone();
        let mut last_check = std::time::Instant::now();
        let mut last_process_count = 0;
        let mut last_menu_update = std::time::Instant::now();
        let is_killing_processes = Arc::new(AtomicBool::new(false));
        // Track when menu was last interacted with to avoid updating during interaction
        let mut last_menu_interaction = std::time::Instant::now() - std::time::Duration::from_secs(10);

        // Give the tray icon time to appear
        info!("Waiting for tray icon to appear...");
        println!("🔍 Look for a white square with red/green center in your status bar!");
        println!("   It should be in the top-right area of your screen.");
        println!(
            "💡 When in full-screen mode, use console mode: ./run.sh --console --ports 3000,8000"
        );

        // Set up menu event handling
        let menu_event_receiver = self.menu_event_receiver.clone();
        let current_processes = self.current_processes.clone();
        let menu_id_to_port = self.menu_id_to_port.clone();
        let args = self.args.clone();

        // Run the event loop
        event_loop.run(move |_event, _elwt| {
            // Handle menu events with crash-safe approach
            if let Ok(event) = menu_event_receiver.try_recv() {
                info!("Menu event received: {:?}", event);
                
                // Record menu interaction time to prevent updates while menu is being used
                last_menu_interaction = std::time::Instant::now();
                
                // Only process if we're not already killing processes
                if !is_killing_processes.load(Ordering::Relaxed) {
                    info!("Processing menu event, starting process killing...");
                    is_killing_processes.store(true, Ordering::Relaxed);
                    
                    // Get current processes for menu handling
                    let current_processes_clone = current_processes.clone();
                    let is_killing_clone = is_killing_processes.clone();
                    let args_clone = args.clone();
                    let menu_id_to_port_clone = menu_id_to_port.clone();
                    
                    std::thread::spawn(move || {
                        // Add a delay to ensure the menu system is stable
                        std::thread::sleep(std::time::Duration::from_millis(100));
                        
                        // Handle different menu actions based on event
                        let result = if let Ok(current_processes_guard) = current_processes_clone.lock() {
                            let processes = &*current_processes_guard;
                            
                            // Parse the menu event to determine action
                            let menu_id = event.id.0.clone();
                            info!("Menu ID: {}", menu_id);
                            
                            // We need to determine which menu item was clicked based on the menu ID
                            // Since the tray-icon crate uses internal IDs, we'll use a different approach
                            // We'll check if this is a known special menu ID first
                            
                            if menu_id == "kill_all" {
                                info!("Kill All Processes clicked, killing all processes...");
                                let ports_to_kill = args_clone.get_ports_to_monitor();
                                Self::kill_all_processes(&ports_to_kill, &args_clone)
                            } else if menu_id == "quit" {
                                info!("Quit clicked, exiting gracefully...");
                                std::process::exit(0);
                            } else {
                                // For individual process clicks, use the menu ID mapping
                                info!("Individual process clicked (ID: {}), looking up port...", menu_id);
                                
                                if let Ok(menu_id_guard) = menu_id_to_port_clone.lock() {
                                    if let Some(&port) = menu_id_guard.get(&menu_id) {
                                        if let Some(process_info) = processes.get(&port) {
                                            info!("Killing specific process on port {} with PID {}", port, process_info.pid);
                                            Self::kill_single_process(process_info, &args_clone)
                                        } else {
                                            error!("Process not found for port {}", port);
                                            Ok(())
                                        }
                                    } else {
                                        warn!("Menu ID {} not found in mapping, ignoring", menu_id);
                                        Ok(())
                                    }
                                } else {
                                    error!("Failed to access menu ID mapping");
                                    Ok(())
                                }
                            }
                        } else {
                            error!("Failed to access current processes");
                            Ok(())
                        };
                        
                        match result {
                            Ok(_) => {
                                info!("Process killing completed successfully");
                                // Reset the flag after a delay to allow menu updates again
                                std::thread::sleep(std::time::Duration::from_secs(1));
                                is_killing_clone.store(false, Ordering::Relaxed);
                            }
                            Err(e) => {
                                error!("Failed to kill processes: {}", e);
                                is_killing_clone.store(false, Ordering::Relaxed);
                            }
                        }
                    });
                } else {
                    info!("Menu event received but already killing processes, ignoring");
                }
            }
            
            // Check for processes every 5 seconds (less frequent to avoid crashes)
            if last_check.elapsed() >= std::time::Duration::from_secs(5) {
                last_check = std::time::Instant::now();
                
                // Get detailed process information with crash-safe approach
                let (process_count, processes) = if args.verbose {
                    // Use ProcessMonitor for verbose information
                    match std::panic::catch_unwind(|| {
                        Self::get_processes_on_ports_verbose(&args.get_ports_to_monitor(), &args)
                    }) {
                        Ok(result) => result,
                        Err(e) => {
                            error!("Panic caught while getting verbose processes: {:?}", e);
                            (0, HashMap::new())
                        }
                    }
                } else {
                    // Use simple process detection for non-verbose mode
                    match std::panic::catch_unwind(|| {
                        Self::get_processes_on_ports(&args.get_ports_to_monitor(), &args)
                    }) {
                        Ok(result) => result,
                        Err(e) => {
                            error!("Panic caught while getting processes: {:?}", e);
                            (0, HashMap::new())
                        }
                    }
                };
                
                let status_info = StatusBarInfo::from_process_count(process_count);
                println!("🔄 Port Status: {} - {}", status_info.text, status_info.tooltip);
                
                // Update current processes
                if let Ok(mut current_processes_guard) = current_processes.lock() {
                    *current_processes_guard = processes.clone();
                }
                
                // Print detected processes with grouping
                if process_count > 0 {
                    println!("📋 Detected Processes:");
                    
                    // Group processes by type
                    let mut grouped_processes: std::collections::HashMap<String, Vec<(&u16, &crate::types::ProcessInfo)>> = std::collections::HashMap::new();
                    let mut ungrouped_processes = Vec::new();
                    
                    for (port, process_info) in &processes {
                        if let Some(ref group) = process_info.process_group {
                            grouped_processes.entry(group.clone()).or_insert_with(Vec::new).push((port, process_info));
                        } else {
                            ungrouped_processes.push((port, process_info));
                        }
                    }
                    
                    // Print grouped processes
                    for (group_name, group_processes) in &grouped_processes {
                        println!("   🔹 {} ({} processes):", group_name, group_processes.len());
                        for (port, process_info) in group_processes {
                            let display_name = process_info.get_display_name();
                            if let (Some(_container_id), Some(container_name)) = (&process_info.container_id, &process_info.container_name) {
                                println!("      • Port {}: {} [Docker: {}]", port, display_name, container_name);
                            } else if args.show_pid {
                                println!("      • Port {}: {} (PID {})", port, display_name, process_info.pid);
                            } else {
                                println!("      • Port {}: {}", port, display_name);
                            }
                        }
                    }
                    
                    // Print ungrouped processes
                    if !ungrouped_processes.is_empty() {
                        println!("   🔹 Other ({} processes):", ungrouped_processes.len());
                        for (port, process_info) in &ungrouped_processes {
                            let display_name = process_info.get_display_name();
                            if let (Some(_container_id), Some(container_name)) = (&process_info.container_id, &process_info.container_name) {
                                println!("      • Port {}: {} [Docker: {}]", port, display_name, container_name);
                            } else if args.show_pid {
                                println!("      • Port {}: {} (PID {})", port, display_name, process_info.pid);
                            } else {
                                println!("      • Port {}: {}", port, display_name);
                            }
                        }
                    }
                } else {
                    println!("📋 No processes detected");
                }
                
                // Update tooltip and icon (avoid menu updates to prevent crashes)
                if let Ok(tray_icon_guard) = tray_icon.lock() {
                    if let Some(ref icon) = *tray_icon_guard {
                        // Update tooltip
                        if let Err(e) = icon.set_tooltip(Some(&status_info.tooltip)) {
                            error!("Failed to update tooltip: {}", e);
                        }
                        
                        // Update icon with new status
                        if let Ok(new_icon) = TrayMenu::create_icon(&status_info.text) {
                            if let Err(e) = icon.set_icon(Some(new_icon)) {
                                error!("Failed to update icon: {}", e);
                            }
                        }
                        
                        // Only update menu if process count changed significantly and we're not killing processes
                        // Add extra delay after killing processes to prevent crashes
                        let process_count_changed = process_count != last_process_count;
                        let enough_time_passed = last_menu_update.elapsed() >= std::time::Duration::from_secs(10); // Increased delay
                        let not_killing = !is_killing_processes.load(Ordering::Relaxed);
                        // Also check that we haven't had a menu interaction recently (prevents crash from issue #30)
                        let no_recent_interaction = last_menu_interaction.elapsed() >= std::time::Duration::from_secs(2);
                        
                        if not_killing && process_count_changed && enough_time_passed && no_recent_interaction {
                            info!("Process count changed from {} to {}, updating menu...", last_process_count, process_count);

                            // Additional validation: ensure all processes in the list are still running
                            let valid_processes: HashMap<u16, crate::types::ProcessInfo> = processes
                                .iter()
                                .filter(|(_, process_info)| Self::is_process_still_running(process_info.pid))
                                .map(|(port, process_info)| (*port, process_info.clone()))
                                .collect();
                            
                            let valid_process_count = valid_processes.len();
                            
                            if valid_process_count != process_count {
                                info!("Process count validation: {} processes reported, {} still running, updating with valid processes", 
                                      process_count, valid_process_count);
                            }
                            
                            // Only proceed if we have valid processes
                            if !valid_processes.is_empty() {
                                // Use a try-catch approach to prevent crashes
                                match std::panic::catch_unwind(|| {
                                    TrayMenu::create_menu_with_verbose(&valid_processes, args.show_pid, args.verbose)
                                }) {
                                    Ok(Ok((new_menu, new_menu_id_to_port))) => {
                                        // SAFETY FIX: Clear the old menu first and wait for macOS to finish cleanup
                                        // This prevents a use-after-free crash when macOS tries to unregister
                                        // key equivalents from menu items that are being deallocated.
                                        // See: https://github.com/treadiehq/port-kill/issues/30
                                        let none_menu: Option<Box<dyn tray_icon::menu::ContextMenu>> = None;
                                        icon.set_menu(none_menu);
                                        
                                        // Give macOS time to fully release the old menu resources
                                        // This delay is critical to prevent the segfault
                                        std::thread::sleep(std::time::Duration::from_millis(50));
                                        
                                        // Now set the new menu
                                        icon.set_menu(Some(Box::new(new_menu)));
                                        
                                        // Store the menu ID to port mapping for event handling
                                        if let Ok(mut menu_id_guard) = menu_id_to_port.lock() {
                                            *menu_id_guard = new_menu_id_to_port;
                                        }
                                        
                                        last_process_count = valid_process_count;
                                        last_menu_update = std::time::Instant::now();
                                        info!("Menu updated successfully for {} processes", valid_process_count);
                                    }
                                    Ok(Err(e)) => {
                                        error!("Failed to create menu: {}", e);
                                    }
                                    Err(e) => {
                                        error!("Menu creation panicked: {:?}, skipping menu update", e);
                                    }
                                }
                            } else {
                                info!("No valid processes found, skipping menu update");
                                last_process_count = 0;
                                last_menu_update = std::time::Instant::now();
                            }
                        } else if process_count_changed {
                            info!("Process count changed from {} to {} but skipping menu update (killing: {}, time passed: {}, no recent interaction: {})",
                                  last_process_count, process_count, !not_killing, enough_time_passed, no_recent_interaction);
                        }
                    }
                }
            }
        })?;

        Ok(())
    }

    pub fn get_processes_on_ports_verbose(
        ports: &[u16],
        args: &Args,
    ) -> (usize, HashMap<u16, crate::types::ProcessInfo>) {
        use crate::process_monitor::ProcessMonitor;
        use crossbeam_channel::bounded;
        use std::collections::HashMap;

        // Create a temporary ProcessMonitor to get verbose information
        let (update_sender, _update_receiver) = bounded(100);
        if let Ok(mut process_monitor) = ProcessMonitor::new_with_performance(
            update_sender,
            ports.to_vec(),
            args.docker,
            args.verbose,
            None,
            true,
        ) {
            // Use tokio runtime to run the async scan_processes method
            let rt = tokio::runtime::Runtime::new().unwrap();
            match rt.block_on(process_monitor.scan_processes()) {
                Ok(processes) => (processes.len(), processes),
                Err(_) => (0, HashMap::new()),
            }
        } else {
            (0, HashMap::new())
        }
    }

    pub fn get_processes_on_ports(
        ports: &[u16],
        args: &Args,
    ) -> (usize, HashMap<u16, crate::types::ProcessInfo>) {
        if ports.is_empty() {
            return (0, HashMap::new());
        }

        #[cfg(target_os = "windows")]
        {
            return Self::get_processes_on_ports_windows(ports, args);
        }

        #[cfg(not(target_os = "windows"))]
        {
            return Self::get_processes_on_ports_unix(ports, args);
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn get_processes_on_ports_unix(
        ports: &[u16],
        args: &Args,
    ) -> (usize, HashMap<u16, crate::types::ProcessInfo>) {
        use std::collections::HashSet;

        const MAX_PORTS_PER_LSOF: usize = 100;
        const LARGE_RANGE_THRESHOLD: usize = 200;
        
        let mut processes = HashMap::new();
        let ports_filter: HashSet<u16> = ports.iter().copied().collect();
        let ignore_ports = args.get_ignore_ports_set();
        let ignore_processes = args.get_ignore_processes_set();

        // For large port ranges, use a single lsof call to get all listening ports
        // and filter afterwards. This is much faster than multiple lsof calls
        // and avoids exceeding command-line argument limits.
        if ports.len() > LARGE_RANGE_THRESHOLD {
            let lsof_args = vec![
                "-sTCP:LISTEN".to_string(),
                "-P".to_string(),
                "-n".to_string(),
                "-iTCP".to_string(), // Get all TCP ports
            ];

            let output = std::process::Command::new("lsof").args(&lsof_args).output();

            match output {
                Ok(output) => {
                    if output.status.success() || !output.stdout.is_empty() {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        Self::parse_lsof_output_filtered(
                            &stdout,
                            &ports_filter,
                            &ignore_ports,
                            &ignore_processes,
                            &mut processes,
                        );
                    }
                }
                Err(e) => {
                    log::warn!("Failed to run lsof for all ports: {}", e);
                }
            }
        } else {
            // For smaller port ranges, use the chunked approach
            for chunk in ports.chunks(MAX_PORTS_PER_LSOF) {
                // Build lsof command with multiple -i flags for each chunk of ports
                let mut lsof_args = vec![
                    "-sTCP:LISTEN".to_string(),
                    "-P".to_string(),
                    "-n".to_string(),
                ];
                for port in chunk {
                    lsof_args.push("-i".to_string());
                    lsof_args.push(format!(":{}", port));
                }

                let output = std::process::Command::new("lsof").args(&lsof_args).output();

                match output {
                    Ok(output) => {
                        if !output.status.success() {
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            if !stderr.trim().is_empty() {
                                log::debug!(
                                    "lsof exited with status {} for ports {:?}: {}",
                                    output.status,
                                    chunk,
                                    stderr.trim()
                                );
                            }
                        }

                        let stdout = String::from_utf8_lossy(&output.stdout);
                        Self::parse_lsof_output_filtered(
                            &stdout,
                            &ports_filter,
                            &ignore_ports,
                            &ignore_processes,
                            &mut processes,
                        );
                    }
                    Err(e) => {
                        log::warn!("Failed to run lsof for ports {:?}: {}", chunk, e);
                    }
                }
            }
        }

        (processes.len(), processes)
    }

    #[cfg(target_os = "windows")]
    fn get_processes_on_ports_windows(
        ports: &[u16],
        args: &Args,
    ) -> (usize, HashMap<u16, crate::types::ProcessInfo>) {
        use std::collections::HashSet;

        let mut processes = HashMap::new();
        let ports_filter: HashSet<u16> = ports.iter().copied().collect();
        let ignore_ports = args.get_ignore_ports_set();
        let ignore_processes = args.get_ignore_processes_set();

        // On Windows, use netstat to find all listening TCP ports
        let output = std::process::Command::new("netstat")
            .args(&["-ano", "-p", "TCP"])
            .output();

        match output {
            Ok(output) => {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    Self::parse_netstat_output(
                        &stdout,
                        &ports_filter,
                        &ignore_ports,
                        &ignore_processes,
                        &mut processes,
                    );
                }
            }
            Err(e) => {
                log::warn!("Failed to run netstat: {}", e);
            }
        }

        (processes.len(), processes)
    }

    #[cfg(target_os = "windows")]
    fn parse_netstat_output(
        stdout: &str,
        ports_filter: &std::collections::HashSet<u16>,
        ignore_ports: &std::collections::HashSet<u16>,
        ignore_processes: &std::collections::HashSet<String>,
        processes: &mut HashMap<u16, crate::types::ProcessInfo>,
    ) {
        for line in stdout.lines() {
            // netstat output format: Proto  Local Address  Foreign Address  State  PID
            if !line.contains("LISTENING") {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }

            // Extract port from local address
            let local_addr = parts[1];
            let port = if let Some(port_str) = local_addr.split(':').last() {
                match port_str.parse::<u16>() {
                    Ok(p) => p,
                    Err(_) => continue,
                }
            } else {
                continue;
            };

            // Filter by port range
            if !ports_filter.is_empty() && !ports_filter.contains(&port) {
                continue;
            }

            // Check ignore lists
            if ignore_ports.contains(&port) {
                log::info!("Ignoring port {} (ignored by user configuration)", port);
                continue;
            }

            // Extract PID
            let pid = match parts[4].parse::<i32>() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Get process name using tasklist
            let process_name = Self::get_process_name_windows(pid).unwrap_or_else(|| "Unknown".to_string());

            if ignore_processes.contains(&process_name) {
                log::info!(
                    "Ignoring process {} (PID {}) on port {} (ignored by user configuration)",
                    process_name,
                    pid,
                    port
                );
                continue;
            }

            log::debug!(
                "Creating ProcessInfo (netstat) for PID {} on port {}",
                pid,
                port
            );

            let mut process_info = crate::types::ProcessInfo {
                pid,
                port,
                command: process_name.clone(),
                name: process_name,
                container_id: None,
                container_name: None,
                command_line: None,
                working_directory: None,
                process_group: None,
                project_name: None,
                cpu_usage: None,
                memory_usage: None,
                memory_percentage: None,
            };

            process_info.process_group = process_info.determine_process_group();
            process_info.project_name = process_info.extract_project_name();

            processes.insert(port, process_info);
        }
    }

    #[cfg(target_os = "windows")]
    fn get_process_name_windows(pid: i32) -> Option<String> {
        let output = std::process::Command::new("tasklist")
            .args(&["/FI", &format!("PID eq {}", pid), "/FO", "CSV", "/NH"])
            .output();

        match output {
            Ok(output) => {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if let Some(line) = stdout.lines().next() {
                        if let Some(name) = line.split(',').next() {
                            return Some(name.trim_matches('"').to_string());
                        }
                    }
                }
            }
            Err(_) => {}
        }

        None
    }

    fn parse_lsof_output_filtered(
        stdout: &str,
        ports_filter: &std::collections::HashSet<u16>,
        ignore_ports: &std::collections::HashSet<u16>,
        ignore_processes: &std::collections::HashSet<String>,
        processes: &mut HashMap<u16, crate::types::ProcessInfo>,
    ) {
        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 9 {
                continue;
            }

            let pid = match parts[1].parse::<i32>() {
                Ok(pid) => pid,
                Err(_) => continue,
            };

            let port_str = parts[8].split(':').last().unwrap_or("0");
            let port = match port_str.parse::<u16>() {
                Ok(port) => port,
                Err(_) => continue,
            };

            // Filter by port range
            if !ports_filter.is_empty() && !ports_filter.contains(&port) {
                continue;
            }

            // Check ignore lists
            if ignore_ports.contains(&port) {
                log::info!(
                    "Ignoring process {} (PID {}) on port {} (ignored port by user configuration)",
                    parts[0],
                    pid,
                    port
                );
                continue;
            }

            if ignore_processes.contains(parts[0]) {
                log::info!(
                    "Ignoring process {} (PID {}) on port {} (ignored process by user configuration)",
                    parts[0],
                    pid,
                    port
                );
                continue;
            }

            log::debug!(
                "Creating ProcessInfo (app.rs) for PID {} on port {} with command_line: None, working_directory: None",
                pid,
                port
            );

            let mut process_info = crate::types::ProcessInfo {
                pid,
                port,
                command: parts[0].to_string(),
                name: parts[0].to_string(),
                container_id: None,
                container_name: None,
                command_line: None,
                working_directory: None,
                process_group: None,
                project_name: None,
                cpu_usage: None,
                memory_usage: None,
                memory_percentage: None,
            };

            process_info.process_group = process_info.determine_process_group();
            process_info.project_name = process_info.extract_project_name();

            processes.insert(port, process_info);
        }
    }

    pub fn kill_all_processes(ports: &[u16], args: &Args) -> Result<()> {
        let port_list = ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        info!("Killing all processes on ports {}...", port_list);

        if ports.is_empty() {
            info!("No ports specified");
            return Ok(());
        }

        #[cfg(target_os = "windows")]
        {
            return Self::kill_all_processes_windows(ports, args);
        }

        #[cfg(not(target_os = "windows"))]
        {
            return Self::kill_all_processes_unix(ports, args);
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn kill_all_processes_unix(ports: &[u16], args: &Args) -> Result<()> {
        use std::collections::HashSet;

        const MAX_PORTS_PER_LSOF: usize = 100;
        const LARGE_RANGE_THRESHOLD: usize = 200;
        
        let ports_filter: HashSet<u16> = ports.iter().copied().collect();
        let ignore_ports = args.get_ignore_ports_set();
        let ignore_processes = args.get_ignore_processes_set();

        let mut pids_to_kill = Vec::new();

        // For large port ranges, use a single lsof call to get all listening ports
        // and filter afterwards. This avoids exceeding command-line argument limits.
        if ports.len() > LARGE_RANGE_THRESHOLD {
            let lsof_args = vec![
                "-sTCP:LISTEN".to_string(),
                "-P".to_string(),
                "-n".to_string(),
                "-iTCP".to_string(), // Get all TCP ports
            ];

            let output = match std::process::Command::new("lsof").args(&lsof_args).output() {
                Ok(output) => output,
                Err(e) => {
                    error!("Failed to run lsof command: {}", e);
                    return Err(anyhow::anyhow!("Failed to run lsof: {}", e));
                }
            };

            let stdout = String::from_utf8_lossy(&output.stdout);
            Self::extract_pids_from_lsof_output(
                &stdout,
                &ports_filter,
                &ignore_ports,
                &ignore_processes,
                &mut pids_to_kill,
            );
        } else {
            // For smaller port ranges, use the chunked approach
            for chunk in ports.chunks(MAX_PORTS_PER_LSOF) {
                let mut lsof_args = vec![
                    "-sTCP:LISTEN".to_string(),
                    "-P".to_string(),
                    "-n".to_string(),
                ];
                for port in chunk {
                    lsof_args.push("-i".to_string());
                    lsof_args.push(format!(":{}", port));
                }

                let output = match std::process::Command::new("lsof").args(&lsof_args).output() {
                    Ok(output) => output,
                    Err(e) => {
                        error!("Failed to run lsof command: {}", e);
                        continue;
                    }
                };

                let stdout = String::from_utf8_lossy(&output.stdout);
                Self::extract_pids_from_lsof_output(
                    &stdout,
                    &ports_filter,
                    &ignore_ports,
                    &ignore_processes,
                    &mut pids_to_kill,
                );
            }
        }

        if pids_to_kill.is_empty() {
            info!("No processes found to kill (all were ignored or none found)");
            return Ok(());
        }

        info!(
            "Found {} processes to kill (after filtering ignored processes)",
            pids_to_kill.len()
        );

        for pid in pids_to_kill {
            info!("Attempting to kill process PID: {}", pid);
            match Self::kill_process(pid) {
                Ok(_) => info!("Successfully killed process PID: {}", pid),
                Err(e) => error!("Failed to kill process {}: {}", pid, e),
            }
        }

        info!("Finished killing all processes");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn kill_all_processes_windows(ports: &[u16], args: &Args) -> Result<()> {
        use std::collections::HashSet;

        let ports_filter: HashSet<u16> = ports.iter().copied().collect();
        let ignore_ports = args.get_ignore_ports_set();
        let ignore_processes = args.get_ignore_processes_set();

        let mut pids_to_kill = Vec::new();

        // On Windows, use netstat to find all listening TCP ports
        let output = match std::process::Command::new("netstat")
            .args(&["-ano", "-p", "TCP"])
            .output()
        {
            Ok(output) => output,
            Err(e) => {
                error!("Failed to run netstat command: {}", e);
                return Err(anyhow::anyhow!("Failed to run netstat: {}", e));
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::extract_pids_from_netstat_output(
            &stdout,
            &ports_filter,
            &ignore_ports,
            &ignore_processes,
            &mut pids_to_kill,
        );

        if pids_to_kill.is_empty() {
            info!("No processes found to kill (all were ignored or none found)");
            return Ok(());
        }

        info!(
            "Found {} processes to kill (after filtering ignored processes)",
            pids_to_kill.len()
        );

        for pid in pids_to_kill {
            info!("Attempting to kill process PID: {}", pid);
            match Self::kill_process(pid) {
                Ok(_) => info!("Successfully killed process PID: {}", pid),
                Err(e) => error!("Failed to kill process {}: {}", pid, e),
            }
        }

        info!("Finished killing all processes");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn extract_pids_from_netstat_output(
        stdout: &str,
        ports_filter: &std::collections::HashSet<u16>,
        ignore_ports: &std::collections::HashSet<u16>,
        ignore_processes: &std::collections::HashSet<String>,
        pids_to_kill: &mut Vec<i32>,
    ) {
        for line in stdout.lines() {
            if !line.contains("LISTENING") {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }

            // Extract port
            let local_addr = parts[1];
            let port = if let Some(port_str) = local_addr.split(':').last() {
                match port_str.parse::<u16>() {
                    Ok(p) => p,
                    Err(_) => continue,
                }
            } else {
                continue;
            };

            // Filter by port range
            if !ports_filter.is_empty() && !ports_filter.contains(&port) {
                continue;
            }

            // Check ignore lists
            if ignore_ports.contains(&port) {
                info!("Ignoring port {} during kill operation (ignored by user configuration)", port);
                continue;
            }

            // Extract PID
            let pid = match parts[4].parse::<i32>() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Get process name
            let process_name = Self::get_process_name_windows(pid).unwrap_or_else(|| "Unknown".to_string());

            if ignore_processes.contains(&process_name) {
                info!(
                    "Ignoring process {} (PID {}) on port {} during kill operation (ignored by user configuration)",
                    process_name, pid, port
                );
                continue;
            }

            if !pids_to_kill.contains(&pid) {
                pids_to_kill.push(pid);
            }
        }
    }

    fn extract_pids_from_lsof_output(
        stdout: &str,
        ports_filter: &std::collections::HashSet<u16>,
        ignore_ports: &std::collections::HashSet<u16>,
        ignore_processes: &std::collections::HashSet<String>,
        pids_to_kill: &mut Vec<i32>,
    ) {
        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 9 {
                continue;
            }

            let pid = match parts[1].parse::<i32>() {
                Ok(pid) => pid,
                Err(_) => continue,
            };

            let port_str = parts[8].split(':').last().unwrap_or("0");
            let port = match port_str.parse::<u16>() {
                Ok(port) => port,
                Err(_) => continue,
            };

            // Filter by port range
            if !ports_filter.is_empty() && !ports_filter.contains(&port) {
                continue;
            }

            let name = parts[0].to_string();

            // Check if this process should be ignored
            if ignore_ports.contains(&port) {
                info!(
                    "Ignoring process {} (PID {}) on port {} during kill operation (ignored by user configuration)",
                    name, pid, port
                );
                continue;
            }

            if ignore_processes.contains(&name) {
                info!(
                    "Ignoring process {} (PID {}) on port {} during kill operation (ignored by user configuration)",
                    name, pid, port
                );
                continue;
            }

            if !pids_to_kill.contains(&pid) {
                pids_to_kill.push(pid);
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn kill_process(pid: i32) -> Result<()> {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        info!("Killing process PID: {} with SIGTERM", pid);

        // First try SIGTERM (graceful termination)
        match kill(Pid::from_raw(pid), Signal::SIGTERM) {
            Ok(_) => info!("SIGTERM sent to PID: {}", pid),
            Err(e) => {
                // Don't fail immediately, just log the error and continue
                warn!(
                    "Failed to send SIGTERM to PID {}: {} (process may already be terminated)",
                    pid, e
                );
            }
        }

        // Wait a bit for graceful termination
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Check if process is still running
        let still_running = std::process::Command::new("ps")
            .args(&["-p", &pid.to_string()])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);

        if still_running {
            // Process still running, send SIGKILL
            info!("Process {} still running, sending SIGKILL", pid);
            match kill(Pid::from_raw(pid), Signal::SIGKILL) {
                Ok(_) => info!("SIGKILL sent to PID: {}", pid),
                Err(e) => {
                    // Log error but don't fail the entire operation
                    warn!(
                        "Failed to send SIGKILL to PID {}: {} (process may be protected)",
                        pid, e
                    );
                }
            }
        } else {
            info!("Process {} terminated gracefully", pid);
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn kill_process(pid: i32) -> Result<()> {
        use std::process::Command;

        info!("Killing process PID: {} on Windows", pid);

        // Use taskkill to terminate the process
        let output = Command::new("taskkill")
            .args(&["/PID", &pid.to_string(), "/F"])
            .output();

        match output {
            Ok(output) => {
                if output.status.success() {
                    info!("Successfully killed process PID: {}", pid);
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    warn!("Failed to kill process PID {}: {}", pid, stderr);
                }
            }
            Err(e) => {
                warn!("Failed to execute taskkill for PID {}: {}", pid, e);
            }
        }

        Ok(())
    }

    pub fn kill_single_process(process_info: &ProcessInfo, args: &Args) -> Result<()> {
        info!("Killing single process PID: {}", process_info.pid);

        // Check if this process should be ignored
        let ignore_ports = args.get_ignore_ports_set();
        let ignore_processes = args.get_ignore_processes_set();
        let ignore_groups = args.get_ignore_groups_set();

        // Check if process name should be ignored
        if ignore_processes.contains(&process_info.name) {
            info!(
                "Ignoring process {} (PID {}) - process name is in ignore list",
                process_info.name, process_info.pid
            );
            return Ok(());
        }

        // Check if process group should be ignored
        if let Some(ref group) = process_info.process_group {
            if ignore_groups.contains(group) {
                info!(
                    "Ignoring process {} (PID {}) - belongs to ignored group {}",
                    process_info.name, process_info.pid, group
                );
                return Ok(());
            }
        }

        // Check if port should be ignored
        if ignore_ports.contains(&process_info.port) {
            info!(
                "Ignoring process on port {} (PID {}) - port is in ignore list",
                process_info.port, process_info.pid
            );
            return Ok(());
        }

        // Process is not ignored, proceed with killing
        Self::kill_process(process_info.pid)
    }

    /// Check if a process is still running by its PID
    fn is_process_still_running(pid: i32) -> bool {
        #[cfg(not(target_os = "windows"))]
        {
            // On Unix-like systems, use ps to check if process exists
            std::process::Command::new("ps")
                .args(&["-p", &pid.to_string()])
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false)
        }

        #[cfg(target_os = "windows")]
        {
            // On Windows, use tasklist to check if process exists
            std::process::Command::new("tasklist")
                .args(&["/FI", &format!("PID eq {}", pid)])
                .output()
                .map(|output| {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    stdout.contains(&pid.to_string())
                })
                .unwrap_or(false)
        }
    }
}
