use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::process::Command;
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::MetadataExt;

use chrono::{DateTime, Local, TimeZone};
use clap::Parser;
use inotify::{Inotify, WatchMask, EventMask};
use log::{info, error};
use serde::{Serialize, Deserialize};
use serde_json;
use tokio::signal;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use procfs::process::Process;

#[derive(Parser, Debug)]
#[command(author, version, about = "Production-ready eBPF file monitor with comprehensive detail extraction", long_about = None)]
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
    
    /// Show file content preview on modifications
    #[arg(short = 'p', long)]
    preview: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct FileMetadata {
    permissions: String,
    permissions_octal: String,
    owner_uid: u32,
    owner_gid: u32,
    owner_name: Option<String>,
    group_name: Option<String>,
    size: u64,
    modified: DateTime<Local>,
    accessed: DateTime<Local>,
    created: Option<DateTime<Local>>,
    inode: u64,
    hard_links: u64,
    file_type: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ProcessDetails {
    pid: i32,
    ppid: Option<i32>,
    name: String,
    exe_path: Option<String>,
    cmdline: Vec<String>,
    cwd: Option<String>,
    uid: u32,
    gid: u32,
    username: Option<String>,
    state: Option<String>,
    start_time: Option<String>,
    cpu_usage: Option<f32>,
    memory_rss: Option<u64>,
    memory_vms: Option<u64>,
    num_threads: Option<i64>,
    open_files: Vec<String>,
    environment: HashMap<String, String>,
    limits: HashMap<String, String>,
    io_stats: Option<IOStats>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct IOStats {
    read_bytes: u64,
    write_bytes: u64,
    read_syscalls: u64,
    write_syscalls: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct FileEvent {
    timestamp: DateTime<Local>,
    timestamp_unix: i64,
    event_type: String,
    file_path: String,
    file_metadata: Option<FileMetadata>,
    process_details: Option<ProcessDetails>,
    operation_details: OperationDetails,
    content_preview: Option<ContentPreview>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct OperationDetails {
    description: String,
    size_change: Option<i64>,
    actor_process: Option<ProcessDetails>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ContentPreview {
    before: Option<String>,
    after: Option<String>,
    diff_summary: Option<String>,
}

struct FileMonitor {
    file_path: String,
    output_format: OutputFormat,
    log_file: Option<String>,
    show_preview: bool,
    last_size: Arc<Mutex<u64>>,
    last_content: Arc<Mutex<Option<String>>>,
    running: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
enum OutputFormat {
    Text,
    Json,
}

impl FileMonitor {
    fn new(file_path: String, output_format: String, log_file: Option<String>, show_preview: bool) -> Self {
        let format = match output_format.as_str() {
            "json" => OutputFormat::Json,
            _ => OutputFormat::Text,
        };
        
        Self {
            file_path,
            output_format: format,
            log_file,
            show_preview,
            last_size: Arc::new(Mutex::new(0)),
            last_content: Arc::new(Mutex::new(None)),
            running: Arc::new(AtomicBool::new(true)),
        }
    }
    
    async fn get_file_metadata(&self) -> Option<FileMetadata> {
        match fs::metadata(&self.file_path) {
            Ok(metadata) => {
                let permissions = metadata.permissions();
                let mode = permissions.mode();
                let permissions_str = format!(
                    "{}{}{}",
                    if metadata.is_dir() { "d" } else { "-" },
                    Self::mode_to_string((mode >> 6) & 0o7),
                    Self::mode_to_string((mode >> 3) & 0o7)
                );
                
                let file_type = if metadata.is_dir() {
                    "directory"
                } else if metadata.is_symlink() {
                    "symlink"
                } else if metadata.is_file() {
                    "regular file"
                } else {
                    "special file"
                };
                
                Some(FileMetadata {
                    permissions: permissions_str,
                    permissions_octal: format!("{:04o}", mode & 0o7777),
                    owner_uid: metadata.uid(),
                    owner_gid: metadata.gid(),
                    owner_name: self.get_username_from_uid(metadata.uid()),
                    group_name: self.get_groupname_from_gid(metadata.gid()),
                    size: metadata.len(),
                    modified: Local.timestamp_opt(metadata.mtime(), 0).single().unwrap_or_else(Local::now),
                    accessed: Local.timestamp_opt(metadata.atime(), 0).single().unwrap_or_else(Local::now),
                    created: None, // Linux doesn't reliably provide creation time
                    inode: metadata.ino(),
                    hard_links: metadata.nlink(),
                    file_type: file_type.to_string(),
                })
            }
            Err(_) => None,
        }
    }
    
    fn mode_to_string(mode: u32) -> String {
        format!(
            "{}{}{}",
            if mode & 0o4 != 0 { "r" } else { "-" },
            if mode & 0o2 != 0 { "w" } else { "-" },
            if mode & 0o1 != 0 { "x" } else { "-" }
        )
    }
    
    async fn get_process_details(&self, pid: i32) -> Option<ProcessDetails> {
        if let Ok(process) = Process::new(pid) {
            let stat = process.stat().ok()?;
            let status = process.status().ok();
            let io = process.io().ok();
            
            let cmdline = process.cmdline().ok().unwrap_or_default();
            let exe_path = process.exe().ok()
                .and_then(|p| p.to_str().map(String::from));
            let cwd = process.cwd().ok()
                .and_then(|p| p.to_str().map(String::from));
            
            // Get open files
            let mut open_files = Vec::new();
            if let Ok(fds) = process.fd() {
                for fd in fds {
                    if let Ok(fd_info) = fd {
                        if let Ok(target) = fs::read_link(format!("/proc/{}/fd/{}", pid, fd_info.fd)) {
                            open_files.push(target.to_string_lossy().to_string());
                        }
                    }
                }
            }
            
            // Get environment variables
            let mut environment = HashMap::new();
            if let Ok(environ) = process.environ() {
                for (key, value) in environ {
                    environment.insert(
                        key.to_string_lossy().to_string(),
                        value.to_string_lossy().to_string()
                    );
                }
            }
            
            // Get resource limits
            let mut limits = HashMap::new();
            if let Ok(limits_info) = process.limits() {
                limits.insert("max_cpu_time".to_string(), format!("{:?}", limits_info.max_cpu_time));
                limits.insert("max_file_size".to_string(), format!("{:?}", limits_info.max_file_size));
                limits.insert("max_data_size".to_string(), format!("{:?}", limits_info.max_data_size));
                limits.insert("max_stack_size".to_string(), format!("{:?}", limits_info.max_stack_size));
                limits.insert("max_core_file_size".to_string(), format!("{:?}", limits_info.max_core_file_size));
                limits.insert("max_resident_set".to_string(), format!("{:?}", limits_info.max_resident_set));
                limits.insert("max_processes".to_string(), format!("{:?}", limits_info.max_processes));
                limits.insert("max_open_files".to_string(), format!("{:?}", limits_info.max_open_files));
                limits.insert("max_locked_memory".to_string(), format!("{:?}", limits_info.max_locked_memory));
                limits.insert("max_address_space".to_string(), format!("{:?}", limits_info.max_address_space));
                limits.insert("max_file_locks".to_string(), format!("{:?}", limits_info.max_file_locks));
            }
            
            // Get IO stats
            let io_stats = io.map(|io| IOStats {
                read_bytes: io.read_bytes,
                write_bytes: io.write_bytes,
                read_syscalls: io.syscr,
                write_syscalls: io.syscw,
            });
            
            // Calculate CPU usage percentage
            let cpu_usage = {
                let ticks_per_second = procfs::ticks_per_second();
                let total_time = stat.utime + stat.stime;
                Some((total_time as f32 / ticks_per_second as f32) * 100.0)
            };
            
            let uid = status.as_ref().map(|s| s.ruid).unwrap_or(0);
            let gid = status.as_ref().map(|s| s.rgid).unwrap_or(0);
            
            Some(ProcessDetails {
                pid,
                ppid: Some(stat.ppid),
                name: stat.comm.clone(),
                exe_path,
                cmdline,
                cwd,
                uid,
                gid,
                username: self.get_username_from_uid(uid),
                state: Some(format!("{:?}", stat.state)),
                start_time: Some(format!("{}", stat.starttime)),
                cpu_usage,
                memory_rss: Some(stat.rss * 4096), // Convert pages to bytes
                memory_vms: Some(stat.vsize),
                num_threads: Some(stat.num_threads),
                open_files,
                environment,
                limits,
                io_stats,
            })
        } else {
            None
        }
    }
    
    async fn detect_actor_process(&self, event_type: &str) -> Option<ProcessDetails> {
        // Try lsof first
        if let Ok(output) = Command::new("lsof")
            .arg(&self.file_path)
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = output_str.lines().collect();
            if lines.len() > 1 {
                for line in lines.iter().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(pid) = parts[1].parse::<i32>() {
                            let cmd = parts[0];
                            if !cmd.contains("ebpf-file-monitor") {
                                return self.get_process_details(pid).await;
                            }
                        }
                    }
                }
            }
        }
        
        // Check running processes for specific operations
        if let Ok(output) = Command::new("ps")
            .args(&["aux"])
            .output()
        {
            let ps_output = String::from_utf8_lossy(&output.stdout);
            let path = PathBuf::from(&self.file_path);
            let filename = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            
            for line in ps_output.lines() {
                let should_check = match event_type {
                    "ACCESS" => line.contains("cat ") || line.contains("less ") || 
                                line.contains("more ") || line.contains("head ") || 
                                line.contains("tail ") || line.contains("grep "),
                    "MODIFY" | "CLOSE_WRITE" => line.contains("vim ") || line.contains("nano ") || 
                                                 line.contains("emacs ") || line.contains("echo ") ||
                                                 line.contains(">>") || line.contains(">"),
                    "DELETE_SELF" => line.contains("rm ") || line.contains("unlink"),
                    _ => false,
                };
                
                if should_check && line.contains(filename) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() > 1 {
                        if let Ok(pid) = parts[1].parse::<i32>() {
                            return self.get_process_details(pid).await;
                        }
                    }
                }
            }
        }
        
        None
    }
    
    async fn get_content_preview(&self) -> Option<String> {
        if !self.show_preview {
            return None;
        }
        
        match fs::read_to_string(&self.file_path) {
            Ok(content) => {
                // Limit preview to first 500 chars
                let preview = if content.len() > 500 {
                    format!("{}...\n[Content truncated, total {} bytes]", 
                        &content[..500], content.len())
                } else {
                    content
                };
                Some(preview)
            }
            Err(_) => None,
        }
    }
    
    async fn get_content_diff(&self, new_content: &str) -> Option<ContentPreview> {
        if !self.show_preview {
            return None;
        }
        
        let last_content = self.last_content.lock().await;
        let before = last_content.clone();
        
        let diff_summary = if let Some(ref old) = before {
            let old_lines = old.lines().count();
            let new_lines = new_content.lines().count();
            let lines_diff = new_lines as i32 - old_lines as i32;
            Some(format!(
                "Lines changed: {:+}, Size changed: {:+} bytes",
                lines_diff,
                new_content.len() as i64 - old.len() as i64
            ))
        } else {
            None
        };
        
        Some(ContentPreview {
            before: before.map(|s| {
                if s.len() > 200 {
                    format!("{}...", &s[..200])
                } else {
                    s
                }
            }),
            after: Some(if new_content.len() > 200 {
                format!("{}...", &new_content[..200])
            } else {
                new_content.to_string()
            }),
            diff_summary,
        })
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
    
    fn get_groupname_from_gid(&self, gid: u32) -> Option<String> {
        if let Ok(output) = Command::new("getent")
            .args(&["group", &gid.to_string()])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if let Some(group_line) = output_str.lines().next() {
                if let Some(group_name) = group_line.split(':').next() {
                    return Some(group_name.to_string());
                }
            }
        }
        None
    }
    
    async fn create_event(&self, event_type: &str, details: &str) -> FileEvent {
        let now = Local::now();
        
        // Get file metadata
        let file_metadata = self.get_file_metadata().await;
        
        // Get monitoring process details
        let monitor_pid = std::process::id() as i32;
        let process_details = self.get_process_details(monitor_pid).await;
        
        // Get actor process details
        let actor_process = if event_type != "MONITOR_START" && event_type != "MONITOR_STOP" {
            self.detect_actor_process(event_type).await
        } else {
            None
        };
        
        // Handle content preview for modifications
        let content_preview = if event_type == "MODIFY" || event_type == "CLOSE_WRITE" {
            if let Some(new_content) = self.get_content_preview().await {
                let preview = self.get_content_diff(&new_content).await;
                *self.last_content.lock().await = Some(new_content);
                preview
            } else {
                None
            }
        } else if event_type == "OPEN" || event_type == "ACCESS" {
            // Store initial content for later comparison
            if let Some(content) = self.get_content_preview().await {
                *self.last_content.lock().await = Some(content);
            }
            None
        } else {
            None
        };
        
        // Calculate size change
        let size_change = if let Some(ref metadata) = file_metadata {
            let last_size = *self.last_size.lock().await;
            if last_size > 0 {
                Some(metadata.size as i64 - last_size as i64)
            } else {
                None
            }
        } else {
            None
        };
        
        // Update last size
        if let Some(ref metadata) = file_metadata {
            *self.last_size.lock().await = metadata.size;
        }
        
        let operation_details = OperationDetails {
            description: details.to_string(),
            size_change,
            actor_process: actor_process.clone(),
        };
        
        FileEvent {
            timestamp: now,
            timestamp_unix: now.timestamp(),
            event_type: event_type.to_string(),
            file_path: self.file_path.clone(),
            file_metadata,
            process_details,
            operation_details,
            content_preview,
        }
    }
    
    fn log_event(&self, event: &FileEvent) {
        let output = match &self.output_format {
            OutputFormat::Json => {
                serde_json::to_string_pretty(event).unwrap_or_else(|_| "Error serializing event".to_string())
            }
            OutputFormat::Text => {
                let mut output = String::new();
                
                // Header
                output.push_str(&format!(
                    "\n{:=<80}\n[{}] EVENT: {}\n{:=<80}\n",
                    "", event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"), event.event_type, ""
                ));
                
                // File Information
                output.push_str(&format!("\n📄 FILE INFORMATION:\n"));
                output.push_str(&format!("   Path: {}\n", event.file_path));
                
                if let Some(ref metadata) = event.file_metadata {
                    output.push_str(&format!("   Type: {}\n", metadata.file_type));
                    output.push_str(&format!("   Size: {} bytes\n", metadata.size));
                    output.push_str(&format!("   Permissions: {} ({})\n", metadata.permissions, metadata.permissions_octal));
                    output.push_str(&format!("   Owner: {} ({}) / Group: {} ({})\n", 
                        metadata.owner_name.as_ref().unwrap_or(&"unknown".to_string()),
                        metadata.owner_uid,
                        metadata.group_name.as_ref().unwrap_or(&"unknown".to_string()),
                        metadata.owner_gid
                    ));
                    output.push_str(&format!("   Inode: {} / Links: {}\n", metadata.inode, metadata.hard_links));
                    output.push_str(&format!("   Modified: {}\n", metadata.modified.format("%Y-%m-%d %H:%M:%S")));
                    output.push_str(&format!("   Accessed: {}\n", metadata.accessed.format("%Y-%m-%d %H:%M:%S")));
                }
                
                // Operation Details
                output.push_str(&format!("\n🔍 OPERATION DETAILS:\n"));
                output.push_str(&format!("   Description: {}\n", event.operation_details.description));
                if let Some(size_change) = event.operation_details.size_change {
                    output.push_str(&format!("   Size Change: {:+} bytes\n", size_change));
                }
                
                // Actor Process Information
                if let Some(ref actor) = event.operation_details.actor_process {
                    output.push_str(&format!("\n👤 ACTOR PROCESS:\n"));
                    output.push_str(&format!("   PID: {} / PPID: {}\n", actor.pid, actor.ppid.unwrap_or(0)));
                    output.push_str(&format!("   Name: {}\n", actor.name));
                    if let Some(ref exe) = actor.exe_path {
                        output.push_str(&format!("   Executable: {}\n", exe));
                    }
                    output.push_str(&format!("   Command: {}\n", actor.cmdline.join(" ")));
                    if let Some(ref cwd) = actor.cwd {
                        output.push_str(&format!("   Working Dir: {}\n", cwd));
                    }
                    output.push_str(&format!("   User: {} ({}) / Group: {}\n", 
                        actor.username.as_ref().unwrap_or(&"unknown".to_string()),
                        actor.uid, actor.gid
                    ));
                    if let Some(ref state) = actor.state {
                        output.push_str(&format!("   State: {}\n", state));
                    }
                    if let Some(cpu) = actor.cpu_usage {
                        output.push_str(&format!("   CPU Usage: {:.2}%\n", cpu));
                    }
                    if let Some(rss) = actor.memory_rss {
                        output.push_str(&format!("   Memory RSS: {} MB\n", rss / 1024 / 1024));
                    }
                    if let Some(vms) = actor.memory_vms {
                        output.push_str(&format!("   Memory VMS: {} MB\n", vms / 1024 / 1024));
                    }
                    if let Some(threads) = actor.num_threads {
                        output.push_str(&format!("   Threads: {}\n", threads));
                    }
                    
                    // IO Stats
                    if let Some(ref io) = actor.io_stats {
                        output.push_str(&format!("\n   📊 IO Statistics:\n"));
                        output.push_str(&format!("      Read: {} bytes ({} syscalls)\n", io.read_bytes, io.read_syscalls));
                        output.push_str(&format!("      Write: {} bytes ({} syscalls)\n", io.write_bytes, io.write_syscalls));
                    }
                    
                    // Open Files (first 5)
                    if !actor.open_files.is_empty() {
                        output.push_str(&format!("\n   📂 Open Files ({} total):\n", actor.open_files.len()));
                        for (i, file) in actor.open_files.iter().take(5).enumerate() {
                            output.push_str(&format!("      {}: {}\n", i + 1, file));
                        }
                        if actor.open_files.len() > 5 {
                            output.push_str(&format!("      ... and {} more\n", actor.open_files.len() - 5));
                        }
                    }
                    
                    // Key Environment Variables
                    if !actor.environment.is_empty() {
                        output.push_str(&format!("\n   🔧 Key Environment Variables:\n"));
                        for key in &["PATH", "HOME", "USER", "SHELL", "PWD"] {
                            if let Some(value) = actor.environment.get(*key) {
                                output.push_str(&format!("      {}: {}\n", key, value));
                            }
                        }
                    }
                }
                
                // Content Preview
                if let Some(ref preview) = event.content_preview {
                    output.push_str(&format!("\n📝 CONTENT PREVIEW:\n"));
                    if let Some(ref diff) = preview.diff_summary {
                        output.push_str(&format!("   {}\n", diff));
                    }
                    if let Some(ref before) = preview.before {
                        output.push_str(&format!("\n   Before:\n   ---\n{}\n   ---\n", 
                            before.lines().map(|l| format!("   {}", l)).collect::<Vec<_>>().join("\n")
                        ));
                    }
                    if let Some(ref after) = preview.after {
                        output.push_str(&format!("\n   After:\n   ---\n{}\n   ---\n", 
                            after.lines().map(|l| format!("   {}", l)).collect::<Vec<_>>().join("\n")
                        ));
                    }
                }
                
                // Monitor Process Info (brief)
                if let Some(ref monitor) = event.process_details {
                    output.push_str(&format!("\n🖥️  MONITOR PROCESS:\n"));
                    output.push_str(&format!("   PID: {} / Name: {}\n", monitor.pid, monitor.name));
                }
                
                output
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
        
        // Store initial file state
        if let Some(metadata) = self.get_file_metadata().await {
            *self.last_size.lock().await = metadata.size;
        }
        if let Some(content) = self.get_content_preview().await {
            *self.last_content.lock().await = Some(content);
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
            ("ACCESS", "File was read/accessed")
        } else if mask.contains(EventMask::MODIFY) {
            ("MODIFY", "File content was modified")
        } else if mask.contains(EventMask::ATTRIB) {
            ("ATTRIB", "File attributes/permissions changed")
        } else if mask.contains(EventMask::CLOSE_WRITE) {
            ("CLOSE_WRITE", "File closed after modification")
        } else if mask.contains(EventMask::CLOSE_NOWRITE) {
            ("CLOSE_NOWRITE", "File closed without modification")
        } else if mask.contains(EventMask::OPEN) {
            ("OPEN", "File was opened")
        } else if mask.contains(EventMask::MOVED_FROM) {
            ("MOVED_FROM", "File was moved from this location")
        } else if mask.contains(EventMask::MOVED_TO) {
            ("MOVED_TO", "File was moved to this location")
        } else if mask.contains(EventMask::CREATE) {
            ("CREATE", "File was created")
        } else if mask.contains(EventMask::DELETE) {
            ("DELETE", "File was deleted")
        } else if mask.contains(EventMask::DELETE_SELF) {
            ("DELETE_SELF", "Monitored file was deleted")
        } else if mask.contains(EventMask::MOVE_SELF) {
            ("MOVE_SELF", "Monitored file was moved/renamed")
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
    
    let monitor = Arc::new(FileMonitor::new(file_path, args.output, args.log_file, args.preview));
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