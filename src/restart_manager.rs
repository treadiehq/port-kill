use crate::types::ProcessHistoryEntry;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::thread;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartInfo {
    pub port: u16,
    pub command: Vec<String>,
    pub working_directory: String,
    pub env_vars: HashMap<String, String>,
    pub last_restarted: chrono::DateTime<chrono::Utc>,
}

pub struct RestartManager {
    restart_history_path: PathBuf,
    restart_info: HashMap<u16, RestartInfo>,
}

impl RestartManager {
    pub fn new() -> Result<Self> {
        let home_dir = Self::get_home_dir();
        let restart_history_path =
            PathBuf::from(format!("{}/.port-kill", home_dir)).join("restart-history.json");

        let mut manager = Self {
            restart_history_path: restart_history_path.clone(),
            restart_info: HashMap::new(),
        };

        // Create the .port-kill directory if it doesn't exist
        if let Some(parent) = restart_history_path.parent() {
            fs::create_dir_all(parent).context("Failed to create .port-kill directory")?;
        }

        // Load existing restart info
        if restart_history_path.exists() {
            manager.load()?;
        }

        Ok(manager)
    }

    /// Save a process for future restart
    pub fn save_process_for_restart(
        &mut self,
        port: u16,
        command_line: &str,
        working_directory: &str,
    ) -> Result<()> {
        // Parse command line into command and args
        let command_parts = crate::command_line::parse_command_line(command_line);

        // Get current environment variables (filter to common dev vars)
        let env_vars = Self::get_relevant_env_vars();

        let restart_info = RestartInfo {
            port,
            command: command_parts,
            working_directory: working_directory.to_string(),
            env_vars,
            last_restarted: chrono::Utc::now(),
        };

        self.restart_info.insert(port, restart_info);
        self.save()?;

        log::info!("Saved restart info for port {}", port);
        Ok(())
    }

    /// Save a process from history entry
    pub fn save_from_history_entry(&mut self, entry: &ProcessHistoryEntry) -> Result<()> {
        if let (Some(ref command_line), Some(ref working_directory)) =
            (&entry.command_line, &entry.working_directory)
        {
            self.save_process_for_restart(entry.port, command_line, working_directory)?;
        }
        Ok(())
    }

    /// Restart a process on a specific port.
    /// Returns the PID of the spawned process. A background reaper thread
    /// ensures the child is waited on so it doesn't become a zombie.
    pub fn restart_port(&mut self, port: u16) -> Result<u32> {
        let restart_info = self
            .restart_info
            .get(&port)
            .ok_or_else(|| anyhow::anyhow!("No restart information found for port {}", port))?;

        log::info!(
            "Restarting process on port {} with command: {:?}",
            port,
            restart_info.command
        );

        let mut child = self.execute_restart(restart_info)?;
        let pid = child.id();

        // Spawn a background thread to reap the child when it exits, preventing zombies.
        // Without this, the child would remain in the process table as a defunct/zombie
        // entry until port-kill itself exits — problematic in long-running modes like --guard.
        thread::spawn(move || {
            let _ = child.wait();
        });

        if let Some(info) = self.restart_info.get_mut(&port) {
            info.last_restarted = chrono::Utc::now();
        }
        let _ = self.save();

        Ok(pid)
    }

    /// Get restart info for a port
    pub fn get_restart_info(&self, port: u16) -> Option<&RestartInfo> {
        self.restart_info.get(&port)
    }

    /// Check if a port has restart information
    pub fn can_restart(&self, port: u16) -> bool {
        self.restart_info.contains_key(&port)
    }

    /// List all ports that can be restarted
    pub fn list_restartable_ports(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = self.restart_info.keys().copied().collect();
        ports.sort();
        ports
    }

    /// Clear restart info for a specific port
    pub fn clear_port(&mut self, port: u16) -> Result<()> {
        self.restart_info.remove(&port);
        self.save()
    }

    /// Clear all restart information
    pub fn clear_all(&mut self) -> Result<()> {
        self.restart_info.clear();
        self.save()
    }

    // Private methods

    fn execute_restart(&self, restart_info: &RestartInfo) -> Result<Child> {
        if restart_info.command.is_empty() {
            return Err(anyhow::anyhow!("No command to execute"));
        }

        let program = &restart_info.command[0];
        let args = &restart_info.command[1..];

        let mut cmd = Command::new(program);
        cmd.args(args)
            .current_dir(&restart_info.working_directory)
            .envs(&restart_info.env_vars);

        // Spawn the process
        let child = cmd
            .spawn()
            .context(format!("Failed to restart process: {}", program))?;

        log::info!(
            "Successfully spawned process with PID {} for port {}",
            child.id(),
            restart_info.port
        );

        Ok(child)
    }

    fn get_relevant_env_vars() -> HashMap<String, String> {
        let mut env_vars = HashMap::new();

        // Common development environment variables
        let relevant_vars = [
            "PATH",
            "NODE_ENV",
            "PYTHON_PATH",
            "PYTHONPATH",
            "GOPATH",
            "CARGO_HOME",
            "RUSTUP_HOME",
            "DATABASE_URL",
            "PORT",
            "HOST",
            "DEBUG",
        ];

        for var_name in &relevant_vars {
            if let Ok(value) = std::env::var(var_name) {
                env_vars.insert(var_name.to_string(), value);
            }
        }

        env_vars
    }

    fn save(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.restart_info)
            .context("Failed to serialize restart info")?;
        fs::write(&self.restart_history_path, json)
            .context("Failed to write restart history file")?;
        Ok(())
    }

    fn load(&mut self) -> Result<()> {
        let json = fs::read_to_string(&self.restart_history_path)
            .context("Failed to read restart history file")?;
        self.restart_info =
            serde_json::from_str(&json).context("Failed to parse restart history file")?;
        Ok(())
    }

    /// Get the default restart history path
    pub fn get_default_path() -> PathBuf {
        let home_dir = Self::get_home_dir();
        PathBuf::from(format!("{}/.port-kill", home_dir)).join("restart-history.json")
    }

    /// Get home directory in a cross-platform way
    fn get_home_dir() -> String {
        // Try HOME first (Unix/Linux/macOS), then USERPROFILE (Windows)
        std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string())
    }
}

impl Default for RestartManager {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            restart_history_path: Self::get_default_path(),
            restart_info: HashMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::command_line::parse_command_line;

    #[test]
    fn test_parse_command_line() {
        let cmd = "npm run dev --port 3000";
        let parts = parse_command_line(cmd);
        assert_eq!(parts, vec!["npm", "run", "dev", "--port", "3000"]);
    }

    #[test]
    fn test_parse_command_line_with_quotes() {
        let cmd = r#"node "my script.js" --arg "value with spaces""#;
        let parts = parse_command_line(cmd);
        assert_eq!(
            parts,
            vec!["node", "my script.js", "--arg", "value with spaces"]
        );
    }
}
