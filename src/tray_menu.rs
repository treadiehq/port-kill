use crate::types::{ProcessInfo, StatusBarInfo};
use anyhow::Result;
use crossbeam_channel::Sender;
use log::debug;
use std::collections::HashMap;
#[cfg(target_os = "macos")]
use tray_icon::{
    menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem},
    Icon,
};

#[cfg(target_os = "macos")]
#[derive(Clone)]
pub struct TrayMenu {
    pub icon: Icon,
    current_processes: HashMap<u16, ProcessInfo>,
    show_pid: bool,
}

#[cfg(target_os = "macos")]
impl TrayMenu {
    pub fn new(_menu_sender: Sender<MenuEvent>) -> Result<Self> {
        // Create a simple icon (we'll use a text-based approach for now)
        let icon = Self::create_icon("0")?;

        // Set up menu event handling
        let sender_clone = _menu_sender.clone();
        MenuEvent::set_event_handler(Some(move |event| {
            let _ = sender_clone.send(event);
        }));

        Ok(Self {
            icon,
            current_processes: HashMap::new(),
            show_pid: false,
        })
    }

    pub fn update_menu(
        &mut self,
        processes: &HashMap<u16, ProcessInfo>,
        show_pid: bool,
    ) -> Result<()> {
        debug!("Updating menu with {} processes", processes.len());

        // Update internal state
        self.current_processes = processes.clone();
        self.show_pid = show_pid;

        Ok(())
    }

    pub fn get_current_menu(&self) -> Result<Menu> {
        let (menu, _) = Self::create_menu(&self.current_processes, self.show_pid)?;
        Ok(menu)
    }

    pub fn update_status(&mut self, status_info: &StatusBarInfo) -> Result<()> {
        debug!("Updating status bar: {}", status_info.text);

        // Update icon with new status text
        self.icon = Self::create_icon(&status_info.text)?;

        Ok(())
    }

    pub fn create_menu(
        processes: &HashMap<u16, ProcessInfo>,
        show_pid: bool,
    ) -> Result<(Menu, HashMap<String, u16>)> {
        Self::create_menu_with_verbose(processes, show_pid, false)
    }

    pub fn create_menu_with_verbose(
        processes: &HashMap<u16, ProcessInfo>,
        show_pid: bool,
        verbose: bool,
    ) -> Result<(Menu, HashMap<String, u16>)> {
        let menu = Menu::new();
        let mut menu_id_to_port = HashMap::new();

        // Add "Kill All Processes" item
        let kill_all_item = MenuItem::with_id(MenuId("kill_all".into()), "Kill All Processes", true, None);
        menu.append(&kill_all_item)?;

        // Add separator
        let separator = PredefinedMenuItem::separator();
        menu.append(&separator)?;

        // Add individual process items
        for (port, process_info) in processes {
            let menu_text = if verbose {
                // Verbose mode: show command line and working directory
                let mut parts = vec![format!("Kill: Port {}: {}", port, process_info.name)];

                if let Some(ref cmd_line) = process_info.command_line {
                    parts.push(format!("({})", cmd_line));
                }

                if show_pid {
                    parts.push(format!("(PID {})", process_info.pid));
                }

                if let Some(ref work_dir) = process_info.working_directory {
                    parts.push(format!("- {}", Self::short_display_path(work_dir)));
                }

                if let (Some(_container_id), Some(container_name)) =
                    (&process_info.container_id, &process_info.container_name)
                {
                    parts.push(format!("[Docker: {}]", container_name));
                }

                parts.join(" ")
            } else if let (Some(_container_id), Some(container_name)) =
                (&process_info.container_id, &process_info.container_name)
            {
                format!(
                    "Kill: Port {}: {} [Docker: {}]",
                    port, process_info.name, container_name
                )
            } else if show_pid {
                format!(
                    "Kill: Port {}: {} (PID {})",
                    port, process_info.name, process_info.pid
                )
            } else {
                format!("Kill: Port {}: {}", port, process_info.name)
            };

            // Create menu item for each process
            let process_item = MenuItem::new(&menu_text, true, None);
            let process_id = process_item.id();
            menu.append(&process_item)?;

            // Store the mapping from menu ID to port
            menu_id_to_port.insert(process_id.0.clone(), *port);
        }

        // Add another separator if there are processes
        if !processes.is_empty() {
            let separator = PredefinedMenuItem::separator();
            menu.append(&separator)?;
        }

        // Add "Quit" item
        let quit_item = MenuItem::with_id(MenuId("quit".into()), "Quit", true, None);
        menu.append(&quit_item)?;

        Ok((menu, menu_id_to_port))
    }

    fn short_display_path(dir: &str) -> String {
        let parts: Vec<&str> = dir.split('/').collect();
        if parts.len() >= 2 {
            parts[parts.len() - 2..].join("/")
        } else {
            dir.to_string()
        }
    }

    pub fn create_icon(text: &str) -> Result<Icon> {
        // Create a simple but visible icon for the status bar
        let icon_data = Self::generate_visible_icon(text);

        // Try different sizes for better compatibility
        match Icon::from_rgba(icon_data.clone(), 16, 16) {
            Ok(icon) => Ok(icon),
            Err(_) => {
                // Fallback to 32x32
                Icon::from_rgba(icon_data, 32, 32)
                    .map_err(|e| anyhow::anyhow!("Failed to create icon: {}", e))
            }
        }
    }

    fn generate_visible_icon(text: &str) -> Vec<u8> {
        // Create a much larger, highly visible 32x32 RGBA icon for the status bar
        let mut icon_data = Vec::new();

        for y in 0..32 {
            for x in 0..32 {
                // Create a very simple, highly visible icon
                let _is_edge = x < 2 || x > 29 || y < 2 || y > 29;
                let _is_center = x >= 14 && x <= 17 && y >= 14 && y <= 17;

                // Create a number display area in the center
                let is_number_area = x >= 12 && x <= 19 && y >= 12 && y <= 19;

                let (r, g, b, a) = if is_number_area {
                    // Parse the number from text (remove any non-numeric characters)
                    let number = text.chars().filter(|c| c.is_numeric()).collect::<String>();
                    let num = number.parse::<u32>().unwrap_or(0);

                    if num == 0 {
                        (0, 255, 0, 255) // Bright green when no processes
                    } else if num <= 9 {
                        // For 1-9 processes, use orange
                        (255, 165, 0, 255) // Orange for 1-9 processes
                    } else {
                        // For 10+ processes, use red to indicate many processes
                        (255, 0, 0, 255) // Red for 10+ processes
                    }
                } else {
                    (255, 255, 255, 255) // Clean white background
                };

                icon_data.extend_from_slice(&[r, g, b, a]);
            }
        }

        icon_data
    }
}
