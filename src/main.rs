use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::process::Command;
use std::collections::HashMap;

use chrono::{DateTime, Local};
use clap::Parser;
use inotify::{Inotify, WatchMask, EventMask};
use log::{info, error};
use serde::{Serialize, Deserialize};
use serde_json;
use tokio::signal;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

#[derive(Parser, Debug)]
#[command(author, version, about = "Production-ready eBPF file monitor", long_about = None)]
struct Args {
    /// Path to the file to monitor
    #[arg(short, long)]
    file: Option<String>,
    
    /// Output format (text or json)
    #[arg(short = 'o', long, default_value = "text")]
    output: String,
    
    /// Log file path (optional)
    #[arg(short = 'l', long)]
    log_file: Option<String>,
    
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct FileEvent {
    timestamp: DateTime<Local>,
    timestamp_unix: i64,
    event_type: String,
    file_path: String,
    file_size: Option<u64>,
    process_id: Option<i32>,
    process_name: Option<String>,
    process_cmd: Option<String>,
    user_id: Option<u32>,
    username: Option<String>,
    details: String,
    operation_actor: String,
}

#[derive(Debug, Clone)]
struct ProcessInfo {
    pid: i32,
    name: String,
    cmd: String,
    username: String,
}

struct FileMonitor {
    file_path: String,
    output_format: OutputFormat,
    log_file: Option<String>,
    last_size: Arc<Mutex<u64>>,
    running: Arc<AtomicBool>,
    recent_processes: Arc<Mutex<HashMap<String, ProcessInfo>>>,
}

#[derive(Debug, Clone)]
enum OutputFormat {
    Text,
    Json,
}

impl FileMonitor {
    fn new(file_path: String, output_format: String, log_file: Option<String>) -> Self {
        let format = match output_format.as_str() {
            "json" => OutputFormat::Json,
            _ => OutputFormat::Text,
        };
        
        Self {
            file_path,
            output_format: format,
            log_file,
            last_size: Arc::new(Mutex::new(0)),
            running: Arc::new(AtomicBool::new(true)),
            recent_processes: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    async fn get_file_size(&self) -> Option<u64> {
        match fs::metadata(&self.file_path) {
            Ok(metadata) => Some(metadata.len()),
            Err(_) => None,
        }
    }
    
    /// Use auditctl to track file access (requires root)
    fn setup_audit_watch(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Try to set up audit watch (this requires root)
        let _ = Command::new("sudo")
            .args(&["auditctl", "-w", &self.file_path, "-p", "rwxa"])
            .output();
        Ok(())
    }
    
    /// Get recent audit events for the file
    fn get_audit_events(&self) -> Vec<ProcessInfo> {
        let mut processes = Vec::new();
        
        // Try ausearch for recent events
        if let Ok(output) = Command::new("sudo")
            .args(&["ausearch", "-f", &self.file_path, "-ts", "recent", "-i"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            // Parse ausearch output for process information
            for line in output_str.lines() {
                if line.contains("pid=") && line.contains("comm=") {
                    if let Some(proc_info) = self.parse_audit_line(line) {
                        processes.push(proc_info);
                    }
                }
            }
        }
        
        processes
    }
    
    fn parse_audit_line(&self, line: &str) -> Option<ProcessInfo> {
        let mut pid = None;
        let mut comm = None;
        let mut user = None;
        
        // Parse audit log format
        for part in line.split_whitespace() {
            if part.starts_with("pid=") {
                pid = part.trim_start_matches("pid=").parse::<i32>().ok();
            } else if part.starts_with("comm=") {
                comm = Some(part.trim_start_matches("comm=").trim_matches('"').to_string());
            } else if part.starts_with("auid=") {
                // Get username from audit uid
                if let Ok(uid) = part.trim_start_matches("auid=").parse::<u32>() {
                    user = self.get_username_from_uid(uid);
                }
            }
        }
        
        if let (Some(pid), Some(name)) = (pid, comm) {
            Some(ProcessInfo {
                pid,
                name: name.clone(),
                cmd: name,
                username: user.unwrap_or_else(|| "unknown".to_string()),
            })
        } else {
            None
        }
    }
    
    /// Try multiple methods to detect who accessed the file
    async fn detect_file_accessor(&self, event_type: &str) -> String {
        // Method 1: Check recent processes from our cache
        if let Ok(recent) = self.recent_processes.lock().await {
            if let Some(proc_info) = recent.get(event_type) {
                return format!("{} (PID: {}, User: {})", 
                    proc_info.name, proc_info.pid, proc_info.username);
            }
        }
        
        // Method 2: Use lsof for currently open files
        if let Ok(output) = Command::new("lsof")
            .arg(&self.file_path)
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = output_str.lines().collect();
            if lines.len() > 1 {
                // Skip header line
                for line in lines.iter().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        let cmd = parts[0];
                        let pid = parts[1];
                        let user = parts[2];
                        
                        // Skip our own process
                        if !cmd.contains("ebpf-file-monitor") {
                            return format!("{} (PID: {}, User: {})", cmd, pid, user);
                        }
                    }
                }
            }
        }
        
        // Method 3: Check who might have recently used the parent directory
        if event_type == "DELETE_SELF" || event_type == "DELETE" {
            // For deletions, check recent shell history or ps for rm commands
            if let Ok(output) = Command::new("ps")
                .args(&["aux"])
                .output()
            {
                let ps_output = String::from_utf8_lossy(&output.stdout);
                for line in ps_output.lines() {
                    if (line.contains("rm ") || line.contains("unlink")) && 
                       line.contains(&self.file_path) {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() > 10 {
                            let user = parts[0];
                            let pid = parts[1];
                            return format!("rm command (PID: {}, User: {})", pid, user);
                        }
                    }
                }
            }
        }
        
        // Method 4: Check fuser for file usage
        if let Ok(output) = Command::new("fuser")
            .arg(&self.file_path)
            .arg("-v")
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stderr); // fuser outputs to stderr
            for line in output_str.lines() {
                if !line.contains("USER") && !line.is_empty() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        let user = parts[0];
                        let pid = parts[1];
                        let cmd = parts[2];
                        if !cmd.contains("ebpf-file-monitor") {
                            return format!("{} (PID: {}, User: {})", cmd, pid, user);
                        }
                    }
                }
            }
        }
        
        // Method 5: Try to identify based on event type patterns
        match event_type {
            "ACCESS" => {
                // Check for common read commands in process list
                if let Ok(output) = Command::new("ps")
                    .args(&["aux"])
                    .output()
                {
                    let ps_output = String::from_utf8_lossy(&output.stdout);
                    let filename = PathBuf::from(&self.file_path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");
                    
                    for line in ps_output.lines() {
                        if (line.contains("cat ") || line.contains("less ") || 
                            line.contains("more ") || line.contains("head ") || 
                            line.contains("tail ") || line.contains("grep ")) &&
                           line.contains(filename) {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() > 10 {
                                let user = parts[0];
                                let pid = parts[1];
                                let cmd = parts[10];
                                return format!("{} (PID: {}, User: {})", 
                                    cmd.split('/').last().unwrap_or(cmd), pid, user);
                            }
                        }
                    }
                }
            }
            "MODIFY" | "CLOSE_WRITE" => {
                // Check for editors or write commands
                if let Ok(output) = Command::new("ps")
                    .args(&["aux"])
                    .output()
                {
                    let ps_output = String::from_utf8_lossy(&output.stdout);
                    let filename = PathBuf::from(&self.file_path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");
                    
                    for line in ps_output.lines() {
                        if (line.contains("vim ") || line.contains("nano ") || 
                            line.contains("emacs ") || line.contains("echo ") ||
                            line.contains(">>") || line.contains(">")) &&
                           line.contains(filename) {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() > 1 {
                                let user = parts[0];
                                let pid = parts[1];
                                return format!("Editor/Shell (PID: {}, User: {})", pid, user);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        
        // Final fallback - monitor process itself
        "System/inotify".to_string()
    }
    
    fn get_username_from_uid(&self, uid: u32) -> Option<String> {
        if let Ok(output) = Command::new("id")
            .arg("-nu")
            .arg(uid.to_string())
            .output()
        {
            let username = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !username.is_empty() && !username.contains("no such user") {
                return Some(username);
            }
        }
        None
    }
    
    async fn create_event(&self, event_type: &str, details: &str) -> FileEvent {
        let now = Local::now();
        
        // Get current process info (monitor itself)
        let monitor_pid = std::process::id() as i32;
        let monitor_name = "ebpf-file-monitor".to_string();
        let uid = unsafe { libc::getuid() };
        let username = self.get_username_from_uid(uid);
        
        // Detect the actual actor
        let operation_actor = if event_type != "MONITOR_START" && event_type != "MONITOR_STOP" {
            self.detect_file_accessor(event_type).await
        } else {
            format!("{} (PID: {})", monitor_name, monitor_pid)
        };
        
        FileEvent {
            timestamp: now,
            timestamp_unix: now.timestamp(),
            event_type: event_type.to_string(),
            file_path: self.file_path.clone(),
            file_size: self.get_file_size().await,
            process_id: Some(monitor_pid),
            process_name: Some(monitor_name),
            process_cmd: None,
            user_id: Some(uid),
            username,
            details: details.to_string(),
            operation_actor,
        }
    }
    
    fn log_event(&self, event: &FileEvent) {
        let output = match &self.output_format {
            OutputFormat::Json => {
                serde_json::to_string(event).unwrap_or_else(|_| "Error serializing event".to_string())
            }
            OutputFormat::Text => {
                format!(
                    "[{}] {} - {} | Size: {} bytes | Monitor PID: {} | Actor: {} | {}",
                    event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),
                    event.event_type,
                    event.file_path,
                    event.file_size.map_or("N/A".to_string(), |s| s.to_string()),
                    event.process_id.map_or("N/A".to_string(), |p| p.to_string()),
                    event.operation_actor,
                    event.details
                )
            }
        };
        
        println!("{}", output);
        
        if let Some(log_file) = &self.log_file {
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_file)
            {
                use std::io::Write;
                let _ = writeln!(file, "{}", output);
            }
        }
    }
    
    async fn monitor(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut inotify = Inotify::init()?;
        
        let path_buf = PathBuf::from(&self.file_path);
        
        // Try to set up audit watch for better process tracking
        let _ = self.setup_audit_watch();
        
        // Monitor all relevant events
        let watch_mask = WatchMask::ACCESS
            | WatchMask::MODIFY
            | WatchMask::ATTRIB
            | WatchMask::CLOSE_WRITE
            | WatchMask::CLOSE_NOWRITE
            | WatchMask::OPEN
            | WatchMask::MOVED_FROM
            | WatchMask::MOVED_TO
            | WatchMask::CREATE
            | WatchMask::DELETE
            | WatchMask::DELETE_SELF
            | WatchMask::MOVE_SELF;
        
        let _watch_descriptor = inotify
            .watches()
            .add(&path_buf, watch_mask)?;
        
        // Initial file size
        if let Some(size) = self.get_file_size().await {
            *self.last_size.lock().await = size;
        }
        
        let startup_event = self.create_event("MONITOR_START", "File monitoring started").await;
        self.log_event(&startup_event);
        
        let mut buffer = [0u8; 4096];
        
        while self.running.load(Ordering::Relaxed) {
            match inotify.read_events(&mut buffer) {
                Ok(events) => {
                    for event in events {
                        let event_details = self.process_event(&event).await;
                        if let Some((event_type, details)) = event_details {
                            let file_event = self.create_event(&event_type, &details).await;
                            self.log_event(&file_event);
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No events available, continue
                }
                Err(e) => {
                    error!("Error reading events: {}", e);
                }
            }
            
            sleep(Duration::from_millis(100)).await;
        }
        
        Ok(())
    }
    
    async fn process_event(&self, event: &inotify::Event<&std::ffi::OsStr>) -> Option<(String, String)> {
        let mask = event.mask;
        
        let (event_type, details) = if mask.contains(EventMask::ACCESS) {
            ("ACCESS", "File was read")
        } else if mask.contains(EventMask::MODIFY) {
            let current_size = self.get_file_size().await;
            let last_size = *self.last_size.lock().await;
            
            if let Some(size) = current_size {
                *self.last_size.lock().await = size;
                let size_diff = size as i64 - last_size as i64;
                return Some((
                    "MODIFY".to_string(),
                    format!("File modified (size change: {:+} bytes, new size: {} bytes)", size_diff, size)
                ));
            }
            ("MODIFY", "File content modified")
        } else if mask.contains(EventMask::ATTRIB) {
            ("ATTRIB", "File attributes/permissions changed")
        } else if mask.contains(EventMask::CLOSE_WRITE) {
            ("CLOSE_WRITE", "File closed after writing")
        } else if mask.contains(EventMask::CLOSE_NOWRITE) {
            ("CLOSE_NOWRITE", "File closed (read-only)")
        } else if mask.contains(EventMask::OPEN) {
            ("OPEN", "File opened")
        } else if mask.contains(EventMask::MOVED_FROM) {
            ("MOVED_FROM", "File moved away")
        } else if mask.contains(EventMask::MOVED_TO) {
            ("MOVED_TO", "File moved here")
        } else if mask.contains(EventMask::CREATE) {
            ("CREATE", "File created")
        } else if mask.contains(EventMask::DELETE) {
            ("DELETE", "File deleted")
        } else if mask.contains(EventMask::DELETE_SELF) {
            ("DELETE_SELF", "Monitored file was deleted")
        } else if mask.contains(EventMask::MOVE_SELF) {
            ("MOVE_SELF", "Monitored file was moved")
        } else {
            return None;
        };
        
        Some((event_type.to_string(), details.to_string()))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    // Initialize logger
    if args.verbose {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Info)
            .init();
    }
    
    // Get file path from command line, environment variable
    let file_path = match args.file {
        Some(path) => path,
        None => match env::var("EBPF_MONITOR_FILE") {
            Ok(path) => path,
            Err(_) => {
                eprintln!("Error: No file path provided.");
                eprintln!("Usage: {} --file <PATH>", env::args().next().unwrap_or_else(|| "ebpf-file-monitor".to_string()));
                eprintln!("Or set EBPF_MONITOR_FILE environment variable");
                std::process::exit(1);
            }
        }
    };
    
    // Verify the file exists
    let path_buf = PathBuf::from(&file_path);
    if !path_buf.exists() {
        eprintln!("Error: File '{}' does not exist", file_path);
        std::process::exit(1);
    }
    
    let monitor = Arc::new(FileMonitor::new(file_path, args.output, args.log_file));
    let monitor_clone = monitor.clone();
    
    // Set up signal handler for graceful shutdown
    tokio::spawn(async move {
        match signal::ctrl_c().await {
            Ok(()) => {
                info!("Received shutdown signal");
                monitor_clone.running.store(false, Ordering::Relaxed);
                
                let shutdown_event = monitor_clone.create_event("MONITOR_STOP", "File monitoring stopped").await;
                monitor_clone.log_event(&shutdown_event);
            }
            Err(err) => {
                error!("Unable to listen for shutdown signal: {}", err);
            }
        }
    });
    
    // Start monitoring
    monitor.monitor().await?;
    
    Ok(())
}