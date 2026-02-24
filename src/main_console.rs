use anyhow::Result;
use clap::Parser;
use log::info;
use port_kill::cache::output::print_or_json;
use port_kill::cache::{
    clean::clean_caches,
    doctor::doctor,
    list::{list_caches, print_list_table},
    restore::restore_last_backup,
};
use port_kill::update_check;
use port_kill::{
    cli::Args,
    console_app::ConsolePortKillApp,
    scripting::{load_script_file, ScriptEngine},
};

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let mut args = Args::parse();

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

    // Handle update check
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

    // Determine if this is a quick operation that will exit early
    // Skip update check for these to avoid 1-5+ second network delays
    let is_quick_operation = args.list_presets
        || args.save_preset.is_some()
        || args.delete_preset.is_some()
        || args.cache.is_some();

    // Check for updates only for long-running operations
    if !is_quick_operation {
        let current_version = env!("CARGO_PKG_VERSION");
        if let Ok(Some(update_info)) = update_check::check_for_updates(current_version).await {
            update_check::print_update_notification(&update_info);
        }
    }

    // Handle preset functionality
    if args.list_presets {
        match Args::list_available_presets() {
            Ok(presets_list) => {
                println!("{}", presets_list);
                return Ok(());
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Save preset
    if let Some(name) = args.save_preset.clone() {
        // Validate arguments before building preset to catch malformed port specifications
        if let Err(e) = args.validate() {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
        let desc = args
            .preset_desc
            .clone()
            .unwrap_or_else(|| "User-defined preset".to_string());
        let preset = args.build_preset_from_args(name.clone(), desc);
        let mut mgr = port_kill::preset_manager::PresetManager::new();
        if let Err(e) = mgr.load_presets() {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
        mgr.add_preset(preset);
        if let Err(e) = mgr.save_presets() {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
        println!("✅ Saved preset '{}'.", name);
        return Ok(());
    }

    // Delete preset
    if let Some(name) = args.delete_preset.clone() {
        let mut mgr = port_kill::preset_manager::PresetManager::new();
        if let Err(e) = mgr.load_presets() {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
        match mgr.remove_preset(&name) {
            Some(_) => {
                if let Err(e) = mgr.save_presets() {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
                println!("🗑️  Deleted preset '{}'.", name);
            }
            None => {
                eprintln!("Preset '{}' not found.", name);
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    // Apply preset if specified
    if let Some(preset_name) = args.preset.clone() {
        if let Err(e) = args.load_preset(&preset_name) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }

    // Validate arguments
    if let Err(e) = args.validate() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    // Handle cache subcommand
    if let Some(cache_cmd) = args.cache.clone() {
        let c = cache_cmd.args();
        if c.list || c.dry_run {
            let resp = list_caches(
                &c.lang,
                c.npx,
                c.js_pm,
                c.hf,
                c.torch,
                c.vercel,
                c.cloudflare,
                c.stale_days,
            )
            .await;
            if c.json {
                print_or_json(&resp, true);
            } else {
                print_list_table(&resp);
            }
            return Ok(());
        }
        if c.clean {
            let resp = clean_caches(
                &c.lang,
                c.npx,
                c.js_pm,
                c.safe_delete,
                c.force,
                c.hf,
                c.torch,
                c.vercel,
                c.cloudflare,
                c.stale_days,
            )
            .await;
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

    // Set up logging level based on verbose flag
    if args.verbose {
        std::env::set_var("RUST_LOG", "debug");
    } else if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    // Initialize logging
    env_logger::init();

    info!("Starting Console Port Kill application...");
    info!("Monitoring: {}", args.get_port_description());

    // Handle special commands
    if args.show_history {
        let app = ConsolePortKillApp::new(args)?;
        app.display_history().await?;
        return Ok(());
    }

    if args.clear_history {
        let app = ConsolePortKillApp::new(args)?;
        app.clear_history().await?;
        return Ok(());
    }

    if args.show_filters {
        let app = ConsolePortKillApp::new(args)?;
        app.display_filter_info().await?;
        return Ok(());
    }

    if args.kill_all {
        let app = ConsolePortKillApp::new(args)?;
        app.kill_all_processes().await?;
        return Ok(());
    }

    if let Some(ref groups) = args.kill_group {
        let groups: Vec<String> = groups.clone();
        let app = ConsolePortKillApp::new(args)?;
        app.kill_by_group(&groups).await?;
        return Ok(());
    }

    if let Some(ref projects) = args.kill_project {
        let projects: Vec<String> = projects.clone();
        let app = ConsolePortKillApp::new(args)?;
        app.kill_by_project(&projects).await?;
        return Ok(());
    }

    if let Some(port) = args.restart {
        let app = ConsolePortKillApp::new(args)?;
        app.restart_port(port).await?;
        return Ok(());
    }

    if args.show_restart_history {
        let app = ConsolePortKillApp::new(args)?;
        app.show_restart_history().await?;
        return Ok(());
    }

    if let Some(port) = args.clear_restart {
        let app = ConsolePortKillApp::new(args)?;
        app.clear_restart_history(port).await?;
        return Ok(());
    }

    if args.detect {
        let app = ConsolePortKillApp::new(args)?;
        app.detect_services().await?;
        return Ok(());
    }

    if let Some(service_name) = args.start.clone() {
        let app = ConsolePortKillApp::new(args)?;
        app.start_service(&service_name).await?;
        return Ok(());
    }

    if args.init_config {
        let app = ConsolePortKillApp::new(args)?;
        app.init_config().await?;
        return Ok(());
    }

    if args.up {
        let app = ConsolePortKillApp::new(args)?;
        app.orchestrate_up().await?;
        return Ok(());
    }

    if args.down {
        let app = ConsolePortKillApp::new(args)?;
        app.orchestrate_down().await?;
        return Ok(());
    }

    if let Some(service_name) = args.restart_service.clone() {
        let app = ConsolePortKillApp::new(args)?;
        app.orchestrate_restart(&service_name).await?;
        return Ok(());
    }

    if args.status {
        let app = ConsolePortKillApp::new(args)?;
        app.orchestrate_status().await?;
        return Ok(());
    }

    if args.reset {
        let app = ConsolePortKillApp::new(args)?;
        app.reset_development_ports().await?;
        return Ok(());
    }

    if args.show_offenders {
        let app = ConsolePortKillApp::new(args)?;
        app.show_frequent_offenders().await?;
        return Ok(());
    }

    if args.show_patterns {
        let app = ConsolePortKillApp::new(args)?;
        app.show_time_patterns().await?;
        return Ok(());
    }

    if args.show_suggestions {
        let app = ConsolePortKillApp::new(args)?;
        app.show_ignore_suggestions().await?;
        return Ok(());
    }

    if args.show_stats {
        let app = ConsolePortKillApp::new(args)?;
        app.show_history_statistics().await?;
        return Ok(());
    }

    if args.show_root_cause {
        let app = ConsolePortKillApp::new(args)?;
        app.show_root_cause_analysis().await?;
        return Ok(());
    }

    if args.audit {
        let app = ConsolePortKillApp::new(args)?;
        app.perform_security_audit().await?;
        return Ok(());
    }

    // Handle remote mode
    if let Some(remote_host) = args.get_remote_host() {
        let app = ConsolePortKillApp::new(args)?;
        app.run_remote_mode(&remote_host).await?;
        return Ok(());
    }

    if args.guard_mode {
        // Extract reservation parameters before moving args
        let reserve_port = args.reserve_port;
        let project_name = args.project_name.clone();
        let process_name = args.process_name.clone();

        let app = ConsolePortKillApp::new(args)?;

        // Check if we need to create a reservation
        if let (Some(port), Some(project_name), Some(process_name)) =
            (reserve_port, project_name, process_name)
        {
            app.reserve_port(port, project_name, process_name).await?;
        }

        app.start_port_guard().await?;

        // Keep the daemon running
        info!("🛡️  Port Guard daemon is running. Press Ctrl+C to stop.");
        tokio::signal::ctrl_c().await?;
        app.stop_port_guard().await?;
        return Ok(());
    }

    if args.show_tree {
        let app = ConsolePortKillApp::new(args)?;
        app.show_process_tree().await?;
        return Ok(());
    }

    // Handle scripting commands
    if let Some(ref script) = args.script {
        let script_content = script.clone();
        let app = ConsolePortKillApp::new(args)?;
        let mut engine = ScriptEngine::new(app.process_monitor(), app.args().clone());
        engine.execute(&script_content).await?;
        return Ok(());
    }

    if let Some(ref script_file) = args.script_file {
        let script_content = load_script_file(script_file)?;
        let app = ConsolePortKillApp::new(args)?;
        let mut engine = ScriptEngine::new(app.process_monitor(), app.args().clone());
        engine.execute(&script_content).await?;
        return Ok(());
    }

    // Create and run the console application
    let app = ConsolePortKillApp::new(args)?;
    app.run().await?;

    info!("Console Port Kill application stopped");
    Ok(())
}
