use std::process::Command;
use std::fs;
use std::path::PathBuf;
use procfs::process::Process;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: i32,
    pub name: String,
    pub cmdline: String,
    pub exe_path: Option<String>,
    pub uid: u32,
    pub username: Option<String>,
}

pub struct ProcessTracker {
    file_path: String,
}

impl ProcessTracker {
    pub fn new(file_path: String) -> Self {
        Self { file_path }
    }
    
    /// Find all processes that have the file open using lsof
    pub fn find_processes_with_file_open(&self) -> Vec<ProcessInfo> {
        let mut processes = Vec::new();
        
        // Use lsof to find processes with file open
        if let Ok(output) = Command::new("lsof")
            .arg("-t")  // PIDs only
            .arg(&self.file_path)
            .output()
        {
            let pids_str = String::from_utf8_lossy(&output.stdout);
            for pid_str in pids_str.lines() {
                if let Ok(pid) = pid_str.trim().parse::<i32>() {
                    if let Some(info) = self.get_process_info(pid) {
                        processes.push(info);
                    }
                }
            }
        }
        
        processes
    }
    
    /// Get detailed information about a specific process
    pub fn get_process_info(&self, pid: i32) -> Option<ProcessInfo> {
        if let Ok(process) = Process::new(pid) {
            let stat = process.stat().ok()?;
            let cmdline = process.cmdline().ok()
                .map(|c| c.join(" "))
                .unwrap_or_else(|| format!("[{}]", stat.comm));
            
            let exe_path = process.exe().ok()
                .and_then(|p| p.to_str().map(String::from));
            
            let uid = process.uid().ok()?;
            let username = self.get_username_from_uid(uid);
            
            Some(ProcessInfo {
                pid,
                name: stat.comm.clone(),
                cmdline,
                exe_path,
                uid,
                username,
            })
        } else {
            None
        }
    }
    
    /// Get the most likely process that performed the operation
    pub fn detect_operation_source(&self) -> Option<ProcessInfo> {
        // First, try to find processes with the file open
        let open_processes = self.find_processes_with_file_open();
        if !open_processes.is_empty() {
            return open_processes.into_iter().next();
        }
        
        // If no processes have it open, check recent processes accessing the file's directory
        if let Some(parent_dir) = PathBuf::from(&self.file_path).parent() {
            if let Ok(output) = Command::new("lsof")
                .arg("+D")  // Search directory
                .arg(parent_dir)
                .arg("-t")
                .output()
            {
                let pids_str = String::from_utf8_lossy(&output.stdout);
                for pid_str in pids_str.lines() {
                    if let Ok(pid) = pid_str.trim().parse::<i32>() {
                        if let Some(info) = self.get_process_info(pid) {
                            // Skip our own monitoring process
                            if !info.name.contains("ebpf-file-monitor") {
                                return Some(info);
                            }
                        }
                    }
                }
            }
        }
        
        None
    }
    
    /// Scan /proc for processes that might have recently accessed the file
    pub fn scan_proc_for_file_access(&self) -> Vec<ProcessInfo> {
        let mut processes = Vec::new();
        
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(file_name) = entry.file_name().into_string() {
                    if let Ok(pid) = file_name.parse::<i32>() {
                        // Check if this process has our file in its fd directory
                        let fd_path = format!("/proc/{}/fd", pid);
                        if let Ok(fd_entries) = fs::read_dir(&fd_path) {
                            for fd_entry in fd_entries.flatten() {
                                if let Ok(link) = fs::read_link(fd_entry.path()) {
                                    if link.to_string_lossy() == self.file_path {
                                        if let Some(info) = self.get_process_info(pid) {
                                            processes.push(info);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        processes
    }
    
    fn get_username_from_uid(&self, uid: u32) -> Option<String> {
        if let Ok(output) = Command::new("id")
            .arg("-nu")
            .arg(uid.to_string())
            .output()
        {
            let username = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !username.is_empty() {
                return Some(username);
            }
        }
        None
    }
    
    /// Get a human-readable description of who performed the operation
    pub fn get_operation_actor(&self, fallback_pid: Option<i32>) -> String {
        // Try to detect the actual process
        if let Some(process) = self.detect_operation_source() {
            return format!(
                "{} (PID: {}, User: {})",
                process.name,
                process.pid,
                process.username.as_deref().unwrap_or("unknown")
            );
        }
        
        // If we have a fallback PID, use it
        if let Some(pid) = fallback_pid {
            if let Some(process) = self.get_process_info(pid) {
                return format!(
                    "{} (PID: {}, User: {})",
                    process.name,
                    process.pid,
                    process.username.as_deref().unwrap_or("unknown")
                );
            }
        }
        
        "Unknown process".to_string()
    }
}

/// Helper to determine the actual operation performer
pub fn identify_operation_source(file_path: &str, event_type: &str) -> String {
    let tracker = ProcessTracker::new(file_path.to_string());
    
    match event_type {
        "DELETE_SELF" | "DELETE" => {
            // For delete operations, the file no longer exists, so check parent directory
            if let Ok(output) = Command::new("ps")
                .args(&["aux"])
                .output()
            {
                let ps_output = String::from_utf8_lossy(&output.stdout);
                for line in ps_output.lines() {
                    if line.contains("rm") && line.contains(file_path) {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() > 1 {
                            return format!("rm command by user {}", parts[0]);
                        }
                    }
                }
            }
        }
        "OPEN" | "ACCESS" => {
            // Check for common programs
            if let Some(process) = tracker.detect_operation_source() {
                return match process.name.as_str() {
                    "cat" => format!("cat command reading file (User: {})", 
                        process.username.as_deref().unwrap_or("unknown")),
                    "vim" | "vi" | "nano" => format!("{} editor opened file (User: {})", 
                        process.name, process.username.as_deref().unwrap_or("unknown")),
                    "less" | "more" => format!("{} pager viewing file (User: {})", 
                        process.name, process.username.as_deref().unwrap_or("unknown")),
                    _ => format!("{} accessed file (User: {})", 
                        process.name, process.username.as_deref().unwrap_or("unknown")),
                };
            }
        }
        _ => {}
    }
    
    tracker.get_operation_actor(None)
}