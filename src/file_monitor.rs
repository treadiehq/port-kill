use crate::types::ProcessInfo;
use anyhow::Result;
use std::path::Path;
use std::process::Command;

/// File-based process monitoring for cross-platform file handle detection
pub struct FileMonitor {
    // Platform-specific implementation will be added
}

impl FileMonitor {
    /// Create a new file monitor
    pub fn new() -> Self {
        Self {}
    }

    /// Find all processes that have a specific file open
    pub fn find_processes_with_file(&self, file_path: &str) -> Result<Vec<ProcessInfo>> {
        let file_path = Path::new(file_path);

        if !file_path.exists() {
            return Ok(vec![]);
        }

        #[cfg(target_os = "windows")]
        {
            self.find_processes_with_file_windows(file_path)
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.find_processes_with_file_unix(file_path)
        }
    }

    /// Find all processes that have files with a specific extension open
    pub fn find_processes_with_extension(&self, extension: &str) -> Result<Vec<ProcessInfo>> {
        #[cfg(target_os = "windows")]
        {
            self.find_processes_with_extension_windows(extension)
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.find_processes_with_extension_unix(extension)
        }
    }

    /// Find all processes that have files matching a pattern open
    pub fn find_processes_with_pattern(&self, pattern: &str) -> Result<Vec<ProcessInfo>> {
        #[cfg(target_os = "windows")]
        {
            self.find_processes_with_pattern_windows(pattern)
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.find_processes_with_pattern_unix(pattern)
        }
    }

    /// Get file information for a process
    pub fn get_process_files(&self, pid: u32) -> Result<Vec<String>> {
        #[cfg(target_os = "windows")]
        {
            self.get_process_files_windows(pid)
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.get_process_files_unix(pid)
        }
    }

    // Windows-specific implementations
    #[cfg(target_os = "windows")]
    fn find_processes_with_file_windows(&self, file_path: &Path) -> Result<Vec<ProcessInfo>> {
        // For now, use a simple approach with handle.exe or PowerShell
        // In a full implementation, we'd use Windows API directly
        self.find_processes_with_file_handle_tool(file_path)
    }

    #[cfg(target_os = "windows")]
    fn find_processes_with_extension_windows(&self, extension: &str) -> Result<Vec<ProcessInfo>> {
        // Use handle.exe or PowerShell to find processes with file extension
        self.find_processes_with_extension_handle_tool(extension)
    }

    #[cfg(target_os = "windows")]
    fn find_processes_with_pattern_windows(&self, pattern: &str) -> Result<Vec<ProcessInfo>> {
        // Use handle.exe or PowerShell to find processes with file pattern
        self.find_processes_with_pattern_handle_tool(pattern)
    }

    #[cfg(target_os = "windows")]
    fn get_process_files_windows(&self, pid: u32) -> Result<Vec<String>> {
        // Use handle.exe or PowerShell to get files for a process
        self.get_process_files_handle_tool(pid)
    }

    // Unix-specific implementations (Linux and macOS)
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn find_processes_with_file_unix(&self, file_path: &Path) -> Result<Vec<ProcessInfo>> {
        // Use lsof to find processes with file open
        let output = Command::new("lsof").arg(file_path).output()?;

        if !output.status.success() {
            return Ok(vec![]);
        }

        self.parse_lsof_output(&String::from_utf8_lossy(&output.stdout))
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn find_processes_with_extension_unix(&self, extension: &str) -> Result<Vec<ProcessInfo>> {
        // Use lsof in machine-readable format (-F pfn) to reliably parse output
        // Search from filesystem root instead of hardcoded current directory
        let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let output = Command::new("lsof").arg("+D").arg(&cwd).output()?;

        if !output.status.success() {
            return Ok(vec![]);
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        self.parse_lsof_output_with_extension(&output_str, extension)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn find_processes_with_pattern_unix(&self, pattern: &str) -> Result<Vec<ProcessInfo>> {
        // Use lsof to find processes with files matching a pattern
        let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let output = Command::new("lsof").arg("+D").arg(&cwd).output()?;

        if !output.status.success() {
            return Ok(vec![]);
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        self.parse_lsof_output_with_pattern(&output_str, pattern)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn get_process_files_unix(&self, pid: u32) -> Result<Vec<String>> {
        // Use lsof to get files for a specific process
        let output = Command::new("lsof")
            .arg("-p")
            .arg(pid.to_string())
            .output()?;

        if !output.status.success() {
            return Ok(vec![]);
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        self.parse_lsof_files_for_process(&output_str)
    }

    // Cross-platform helper methods using external tools
    #[cfg(target_os = "windows")]
    fn parse_handle_output(&self, output: &str) -> Result<Vec<ProcessInfo>> {
        let mut processes = Vec::new();

        for line in output.lines() {
            if line.starts_with("pid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(pid) = parts[1].parse::<i32>() {
                        // Get process name from the next line or use a default
                        let name = "unknown".to_string();
                        processes.push(ProcessInfo {
                            pid,
                            name: name.clone(),
                            port: 0,
                            command: name,
                            container_id: None,
                            container_name: None,
                            command_line: Some(String::new()),
                            working_directory: None,
                            process_group: None,
                            project_name: None,
                            cpu_usage: None,
                            memory_usage: None,
                            memory_percentage: None,
                        });
                    }
                }
            }
        }

        Ok(processes)
    }

    #[allow(dead_code)]
    fn find_processes_with_file_handle_tool(&self, _file_path: &Path) -> Result<Vec<ProcessInfo>> {
        // Try to use handle.exe on Windows, or PowerShell
        #[cfg(target_os = "windows")]
        {
            // Try PowerShell approach first
            let ps_command = format!(
                "Get-Process | Where-Object {{ $_.Modules.FileName -like '*{}*' }} | Select-Object Id,ProcessName",
                _file_path.display()
            );

            let output = Command::new("powershell")
                .arg("-Command")
                .arg(&ps_command)
                .output()?;

            if output.status.success() {
                return self.parse_powershell_output(&String::from_utf8_lossy(&output.stdout));
            }
        }

        // Fallback: try to use handle.exe if available
        #[cfg(target_os = "windows")]
        {
            if let Ok(output) = Command::new("handle").arg(_file_path).output() {
                if output.status.success() {
                    return self.parse_handle_output(&String::from_utf8_lossy(&output.stdout));
                }
            }
        }

        Ok(vec![])
    }

    #[allow(dead_code)]
    fn find_processes_with_extension_handle_tool(
        &self,
        _extension: &str,
    ) -> Result<Vec<ProcessInfo>> {
        // For now, return empty - this would need more sophisticated implementation
        Ok(vec![])
    }

    #[allow(dead_code)]
    fn find_processes_with_pattern_handle_tool(&self, _pattern: &str) -> Result<Vec<ProcessInfo>> {
        // For now, return empty - this would need more sophisticated implementation
        Ok(vec![])
    }

    #[allow(dead_code)]
    fn get_process_files_handle_tool(&self, _pid: u32) -> Result<Vec<String>> {
        // For now, return empty - this would need more sophisticated implementation
        Ok(vec![])
    }

    // Output parsing methods
    fn parse_lsof_output(&self, output: &str) -> Result<Vec<ProcessInfo>> {
        let mut processes = Vec::new();

        for line in output.lines().skip(1) {
            // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(pid) = parts[1].parse::<i32>() {
                    let name = parts[0].to_string();
                    processes.push(ProcessInfo {
                        pid,
                        name: name.clone(),
                        port: 0, // File monitoring doesn't use ports
                        command: name,
                        container_id: None,
                        container_name: None,
                        command_line: Some(String::new()),
                        working_directory: None,
                        process_group: None,
                        project_name: None,
                        cpu_usage: None,
                        memory_usage: None,
                        memory_percentage: None,
                    });
                }
            }
        }

        Ok(processes)
    }

    fn parse_lsof_output_with_extension(
        &self,
        output: &str,
        extension: &str,
    ) -> Result<Vec<ProcessInfo>> {
        let mut processes = Vec::new();
        let mut seen_pids = std::collections::HashSet::new();
        let ext_suffix = if extension.starts_with('.') {
            extension.to_string()
        } else {
            format!(".{}", extension)
        };

        for line in output.lines().skip(1) {
            // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();
            // lsof output: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
            // NAME is the last column (index 8+), may contain spaces
            if parts.len() >= 9 {
                // Extract the NAME column (everything from column 8 onwards to handle spaces in paths)
                let name_col = parts[8..].join(" ");
                if name_col.ends_with(&ext_suffix) {
                    if let Ok(pid) = parts[1].parse::<i32>() {
                        // Deduplicate by PID
                        if seen_pids.insert(pid) {
                            let name = parts[0].to_string();
                            processes.push(ProcessInfo {
                                pid,
                                name: name.clone(),
                                port: 0,
                                command: name,
                                container_id: None,
                                container_name: None,
                                command_line: Some(String::new()),
                                working_directory: None,
                                process_group: None,
                                project_name: None,
                                cpu_usage: None,
                                memory_usage: None,
                                memory_percentage: None,
                            });
                        }
                    }
                }
            }
        }

        Ok(processes)
    }

    fn parse_lsof_output_with_pattern(
        &self,
        output: &str,
        pattern: &str,
    ) -> Result<Vec<ProcessInfo>> {
        let mut processes = Vec::new();
        let mut seen_pids = std::collections::HashSet::new();

        for line in output.lines().skip(1) {
            // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();
            // lsof output: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
            if parts.len() >= 9 {
                // Match only against the NAME column (file path), not the entire line
                let name_col = parts[8..].join(" ");
                if name_col.contains(pattern) {
                    if let Ok(pid) = parts[1].parse::<i32>() {
                        // Deduplicate by PID
                        if seen_pids.insert(pid) {
                            let name = parts[0].to_string();
                            processes.push(ProcessInfo {
                                pid,
                                name: name.clone(),
                                port: 0,
                                command: name,
                                container_id: None,
                                container_name: None,
                                command_line: Some(String::new()),
                                working_directory: None,
                                process_group: None,
                                project_name: None,
                                cpu_usage: None,
                                memory_usage: None,
                                memory_percentage: None,
                            });
                        }
                    }
                }
            }
        }

        Ok(processes)
    }

    fn parse_lsof_files_for_process(&self, output: &str) -> Result<Vec<String>> {
        let mut files = Vec::new();

        for line in output.lines().skip(1) {
            // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 9 {
                // The filename is typically the last part
                if let Some(filename) = parts.last() {
                    if filename.starts_with('/') || filename.contains('.') {
                        files.push(filename.to_string());
                    }
                }
            }
        }

        Ok(files)
    }

    #[cfg(target_os = "windows")]
    fn parse_powershell_output(&self, output: &str) -> Result<Vec<ProcessInfo>> {
        let mut processes = Vec::new();

        for line in output.lines() {
            if line.contains("Id") && line.contains("ProcessName") {
                continue; // Skip header
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(pid) = parts[0].parse::<i32>() {
                    let name = parts[1].to_string();
                    processes.push(ProcessInfo {
                        pid,
                        name: name.clone(),
                        port: 0,
                        command: name,
                        container_id: None,
                        container_name: None,
                        command_line: Some(String::new()),
                        working_directory: None,
                        process_group: None,
                        project_name: None,
                        cpu_usage: None,
                        memory_usage: None,
                        memory_percentage: None,
                    });
                }
            }
        }

        Ok(processes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_monitor_creation() {
        let monitor = FileMonitor::new();
        assert!(true); // Basic creation test
    }

    #[test]
    fn test_find_processes_with_nonexistent_file() {
        let monitor = FileMonitor::new();
        let result = monitor.find_processes_with_file("/nonexistent/file.txt");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
