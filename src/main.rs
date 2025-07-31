use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{DateTime, Local};
use clap::Parser;
use inotify::{Inotify, WatchMask, EventMask};
use log::{info, error};
use procfs::process::Process;
use serde::{Serialize, Deserialize};
use serde_json;
use tokio::signal;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

mod process_tracker;
use process_tracker::{ProcessTracker, identify_operation_source};

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
    details: String,
    operation_source: Option<String>,
}

struct FileMonitor {
    file_path: String,
    output_format: OutputFormat,
    log_file: Option<String>,
    last_size: Arc<Mutex<u64>>,
    running: Arc<AtomicBool>,
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
        }
    }
    
    async fn get_file_size(&self) -> Option<u64> {
        match fs::metadata(&self.file_path) {
            Ok(metadata) => Some(metadata.len()),
            Err(_) => None,
        }
    }
    
    fn get_process_info(&self) -> (Option<i32>, Option<String>, Option<String>, Option<u32>) {
        match Process::myself() {
            Ok(process) => {
                let pid = process.pid();
                let name = process.stat().ok().map(|s| s.comm.clone());
                let cmdline = process.cmdline().ok().map(|c| c.join(" "));
                let uid = process.uid().ok();
                (Some(pid), name, cmdline, uid)
            }
            Err(_) => (None, None, None, None),
        }
    }
    
    fn create_event(&self, event_type: &str, details: &str) -> FileEvent {
        let now = Local::now();
        let (pid, name, cmd, uid) = self.get_process_info();
        
        // Get the actual operation source
        let operation_source = if event_type != "MONITOR_START" && event_type != "MONITOR_STOP" {
            Some(identify_operation_source(&self.file_path, event_type))
        } else {
            None
        };
        
        FileEvent {
            timestamp: now,
            timestamp_unix: now.timestamp(),
            event_type: event_type.to_string(),
            file_path: self.file_path.clone(),
            file_size: tokio::task::block_in_place(|| {
                futures::executor::block_on(self.get_file_size())
            }),
            process_id: pid,
            process_name: name,
            process_cmd: cmd,
            user_id: uid,
            details: details.to_string(),
            operation_source,
        }
    }
    
    fn log_event(&self, event: &FileEvent) {
        let output = match &self.output_format {
            OutputFormat::Json => {
                serde_json::to_string(event).unwrap_or_else(|_| "Error serializing event".to_string())
            }
            OutputFormat::Text => {
                let mut output = format!(
                    "[{}] {} - {} | Size: {} bytes | PID: {} ({}) | Details: {}",
                    event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),
                    event.event_type,
                    event.file_path,
                    event.file_size.map_or("N/A".to_string(), |s| s.to_string()),
                    event.process_id.map_or("N/A".to_string(), |p| p.to_string()),
                    event.process_name.as_deref().unwrap_or("N/A"),
                    event.details
                );
                
                if let Some(source) = &event.operation_source {
                    output.push_str(&format!(" | Operation by: {}", source));
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
        
        // Initial file size
        if let Some(size) = self.get_file_size().await {
            *self.last_size.lock().await = size;
        }
        
        let startup_event = self.create_event("MONITOR_START", "File monitoring started");
        self.log_event(&startup_event);
        
        let mut buffer = [0u8; 4096];
        
        while self.running.load(Ordering::Relaxed) {
            match inotify.read_events(&mut buffer) {
                Ok(events) => {
                    for event in events {
                        let event_details = self.process_event(&event).await;
                        if let Some((event_type, details)) = event_details {
                            let file_event = self.create_event(&event_type, &details);
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
            // Get more context about the access
            let tracker = ProcessTracker::new(self.file_path.clone());
            let access_detail = if let Some(process) = tracker.detect_operation_source() {
                match process.name.as_str() {
                    "cat" => "File contents displayed",
                    "head" | "tail" => "File partially read",
                    "grep" => "File searched",
                    _ => "File was accessed (read)",
                }
            } else {
                "File was accessed (read)"
            };
            ("ACCESS", access_detail)
        } else if mask.contains(EventMask::MODIFY) {
            let current_size = self.get_file_size().await;
            let last_size = *self.last_size.lock().await;
            
            if let Some(size) = current_size {
                *self.last_size.lock().await = size;
                let size_diff = size as i64 - last_size as i64;
                return Some((
                    "MODIFY".to_string(),
                    format!("File content modified (size change: {:+} bytes, new size: {} bytes)", size_diff, size)
                ));
            }
            ("MODIFY", "File content modified")
        } else if mask.contains(EventMask::ATTRIB) {
            ("ATTRIB", "File attributes changed")
        } else if mask.contains(EventMask::CLOSE_WRITE) {
            ("CLOSE_WRITE", "File closed after writing")
        } else if mask.contains(EventMask::CLOSE_NOWRITE) {
            ("CLOSE_NOWRITE", "File closed without writing")
        } else if mask.contains(EventMask::OPEN) {
            ("OPEN", "File was opened")
        } else if mask.contains(EventMask::MOVED_FROM) {
            ("MOVED_FROM", "File moved from this location")
        } else if mask.contains(EventMask::MOVED_TO) {
            ("MOVED_TO", "File moved to this location")
        } else if mask.contains(EventMask::CREATE) {
            ("CREATE", "File was created")
        } else if mask.contains(EventMask::DELETE) {
            ("DELETE", "File was deleted")
        } else if mask.contains(EventMask::DELETE_SELF) {
            ("DELETE_SELF", "Watched file was deleted")
        } else if mask.contains(EventMask::MOVE_SELF) {
            ("MOVE_SELF", "Watched file was moved")
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
                
                let shutdown_event = monitor_clone.create_event("MONITOR_STOP", "File monitoring stopped");
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