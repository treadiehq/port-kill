use port_kill::{
    cli::Args,
    console_app::ConsolePortKillApp,
    types::{ProcessInfo, StatusBarInfo},
    process_monitor::{get_processes_on_ports, kill_all_processes},
};
use port_kill::cache::{
    list::{list_caches, print_list_table},
    clean::clean_caches,
    restore::restore_last_backup,
    doctor::doctor,
};
use port_kill::cache::output::print_or_json;
use port_kill::update_check;
use tray_item::TrayItem;
use anyhow::Result;
use clap::Parser;
use log::{error, info};
use std::collections::HashMap;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();
    
    // Validate arguments
    if let Err(e) = args.validate() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
    
    // Set up logging level based on log_level argument
    let log_level = if args.verbose {
        // Verbose flag overrides log_level for backward compatibility
        "debug"
    } else {
        args.log_level.to_rust_log()
    };
    std::env::set_var("RUST_LOG", log_level);
    
    // Initialize logging
    env_logger::init();
    
    info!("Starting Port Kill application on Windows...");
    info!("Monitoring: {}", args.get_port_description());
    
    // Handle self-update
    if args.self_update {
        match update_check::self_update().await {
            Ok(()) => return Ok(()),
            Err(e) => {
                eprintln!("⚠️  Self-update failed: {}", e);
                return Ok(());
            }
        }
    }

    // Handle explicit update check
    if args.check_updates {
        let current_version = env!("CARGO_PKG_VERSION");
        match update_check::check_for_updates(current_version).await {
            Ok(Some(update_info)) => {
                update_check::print_update_check_result(&update_info);
                return Ok(());
            }
            Ok(None) => {
                println!("✅ You're running the latest version ({})", current_version);
                return Ok(());
            }
            Err(e) => {
                eprintln!("⚠️  Could not check for updates: {}", e);
                return Ok(());
            }
        }
    }

    // Background update notification (non-blocking)
    let current_version = env!("CARGO_PKG_VERSION");
    if let Ok(Some(update_info)) = update_check::check_for_updates(current_version).await {
        update_check::print_update_notification(&update_info);
    }

    // Handle cache subcommand on Windows too (parity with console binary)
    if let Some(cache_cmd) = args.cache.clone() {
        let c = cache_cmd.args();
        if c.list || c.dry_run {
            let resp = list_caches(&c.lang, c.npx, c.js_pm, c.hf, c.torch, c.vercel, c.cloudflare, c.stale_days).await;
            if c.json {
                print_or_json(&resp, true);
            } else {
                print_list_table(&resp);
            }
            return Ok(());
        }
        if c.clean {
            let resp = clean_caches(&c.lang, c.npx, c.js_pm, c.safe_delete, c.force, c.hf, c.torch, c.vercel, c.cloudflare, c.stale_days).await;
            print_or_json(&resp, c.json);
            return Ok(());
        }
        if c.restore_last {
            let resp = restore_last_backup().await;
            print_or_json(&resp, c.json);
            if resp.error.is_some() {
                std::process::exit(1);
            }
            return Ok(());
        }
        if c.doctor {
            let report = doctor().await;
            print_or_json(&report, c.json);
            return Ok(());
        }
    }
    
    // Check if running in console mode
    if args.console {
        // Use console mode (works identically to macOS/Linux)
        let console_app = ConsolePortKillApp::new(args)?;
        console_app.run().await
    } else {
        // Use Windows tray mode; on failure, fall back to console
        match run_windows_tray_mode(args.clone()).await {
            Ok(()) => Ok(()),
            Err(e) => {
                log::warn!("Tray mode failed on Windows ({}). Falling back to console mode...", e);
                let console_app = ConsolePortKillApp::new(args)?;
                console_app.run().await
            }
        }
    }
}

async fn run_windows_tray_mode(args: Args) -> Result<()> {
    info!("Starting Windows tray mode...");
    
    // Create the tray item using the embedded icon resource (ID: 1)
    let mut tray = TrayItem::new("Port Kill", tray_item::IconSource::Resource("1"))
        .map_err(|e| anyhow::anyhow!("Failed to create Windows tray item: {}", e))?;
    
    info!("Windows tray created successfully!");
    println!("🔍 Look for the Port Kill icon in your system tray!");
    println!("   It should appear in your Windows notification area.");
    
    // Create channels for communication
    let (menu_sender, menu_receiver) = std::sync::mpsc::channel();
    
    // Add menu items
    let sender_clone = menu_sender.clone();
    tray.add_menu_item("Kill All Processes", move || {
        if let Err(e) = sender_clone.send("kill_all") {
            error!("Failed to send kill_all event: {}", e);
        }
    }).map_err(|e| anyhow::anyhow!("Failed to add Kill All menu item: {}", e))?;
    
    let sender_clone = menu_sender.clone();
    tray.add_menu_item("Quit", move || {
        if let Err(e) = sender_clone.send("quit") {
            error!("Failed to send quit event: {}", e);
        }
    }).map_err(|e| anyhow::anyhow!("Failed to add Quit menu item: {}", e))?;
    
    // Main monitoring loop
    let mut last_check = std::time::Instant::now();
    let mut last_process_count = 0;
    let mut last_processes = HashMap::new();
    
    loop {
        // Check for menu events
        if let Ok(event) = menu_receiver.try_recv() {
            match event {
                "kill_all" => {
                    info!("Kill All Processes clicked");
                    let ports_to_kill = args.get_ports_to_monitor();
                    let args_clone = args.clone();

                    // Use spawn_blocking to avoid blocking the async runtime
                    // This keeps the tray UI responsive during kill operations
                    let handle = tokio::task::spawn_blocking(move || {
                        kill_all_processes(&ports_to_kill, &args_clone)
                    });

                    match handle.await {
                        Ok(Ok(())) => println!("✅ All processes killed successfully"),
                        Ok(Err(e)) => error!("Failed to kill all processes: {}", e),
                        Err(e) => error!("Kill task panicked: {}", e),
                    }
                }
                "quit" => {
                    info!("Quit clicked, exiting...");
                    break;
                }
                _ => {
                    info!("Unknown menu event: {}", event);
                }
            }
        }
        
        // Check for processes every 5 seconds
        if last_check.elapsed() >= Duration::from_secs(5) {
            last_check = std::time::Instant::now();
            
            // Get process information using spawn_blocking to avoid blocking the async runtime
            let ports = args.get_ports_to_monitor();
            let args_clone = args.clone();
            let result = tokio::task::spawn_blocking(move || {
                get_processes_on_ports(&ports, &args_clone)
            }).await;

            let (process_count, processes) = match result {
                Ok(data) => data,
                Err(e) => {
                    error!("Process scan task panicked: {}", e);
                    continue;
                }
            };
            let status_info = StatusBarInfo::from_process_count(process_count);
            
            // Only update if processes have actually changed
            if process_count != last_process_count || processes != last_processes {
                info!("Process list changed: {} processes (was: {})", process_count, last_process_count);
                
                // Print status to console
                println!("🔄 Port Status: {} - {}", status_info.text, status_info.tooltip);
                
                // Print detected processes with grouping
                if process_count > 0 {
                    println!("📋 Detected Processes:");
                    
                    // Group processes by type
                    let mut grouped_processes: std::collections::HashMap<String, Vec<(&u16, &ProcessInfo)>> = std::collections::HashMap::new();
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
                            if args.verbose {
                                // Verbose mode: show command line and working directory
                                let mut parts = vec![format!("      • Port {}: {}", port, display_name)];
                                
                                if let Some(ref cmd_line) = process_info.command_line {
                                    parts.push(format!("({})", cmd_line));
                                }
                                
                                if args.show_pid {
                                    parts.push(format!("(PID {})", process_info.pid));
                                }
                                
                                if let Some(ref work_dir) = process_info.working_directory {
                                    parts.push(format!("- {}", work_dir));
                                }
                                
                                if let (Some(_container_id), Some(container_name)) = (&process_info.container_id, &process_info.container_name) {
                                    parts.push(format!("[Docker: {}]", container_name));
                                }
                                
                                println!("{}", parts.join(" "));
                            } else if let (Some(_container_id), Some(container_name)) = (&process_info.container_id, &process_info.container_name) {
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
                            if args.verbose {
                                // Verbose mode: show command line and working directory
                                let mut parts = vec![format!("      • Port {}: {}", port, display_name)];
                                
                                if let Some(ref cmd_line) = process_info.command_line {
                                    parts.push(format!("({})", cmd_line));
                                }
                                
                                if args.show_pid {
                                    parts.push(format!("(PID {})", process_info.pid));
                                }
                                
                                if let Some(ref work_dir) = process_info.working_directory {
                                    parts.push(format!("- {}", work_dir));
                                }
                                
                                if let (Some(_container_id), Some(container_name)) = (&process_info.container_id, &process_info.container_name) {
                                    parts.push(format!("[Docker: {}]", container_name));
                                }
                                
                                println!("{}", parts.join(" "));
                            } else if let (Some(_container_id), Some(container_name)) = (&process_info.container_id, &process_info.container_name) {
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
                
                // Update our tracking
                last_process_count = process_count;
                last_processes = processes;
            }
        }
        
        // Small delay to prevent busy waiting - use tokio sleep for async compatibility
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    
    info!("Port Kill application exiting...");
    Ok(())
}









