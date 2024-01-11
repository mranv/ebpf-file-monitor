use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use inotify::{
    Inotify, WatchMask, WatchDescriptor, EventMask,
};
use tokio::time::sleep;

const FILE_PATH: &str = "/home/mranv/Desktop/ebpf-file-monitor/example.txt";
const MONITOR_INTERVAL_SECONDS: u64 = 1; // Change this to your desired interval

#[tokio::main]
async fn main() {
    // Create an inotify instance
    let mut inotify = Inotify::init().expect("Failed to initialize inotify");

    // Add a watch for the specified file
    let watch_descriptor = inotify
        .add_watch(PathBuf::from(FILE_PATH), WatchMask::MODIFY)
        .expect("Failed to add watch for file");

    // Run the monitoring loop
    loop {
        // Synchronous event handling
        handle_events(&mut inotify, &watch_descriptor).await;

        // Sleep for the specified interval
        sleep(Duration::from_secs(MONITOR_INTERVAL_SECONDS)).await;
    }
}

async fn handle_events(inotify: &mut Inotify, watch_descriptor: &WatchDescriptor) {
    let mut buffer = [0u8; 4096];
    match inotify.read_events_blocking(&mut buffer) {
        Ok(events) => {
            for event in events {
                if event.mask.contains(EventMask::MODIFY) {
                    let current_time = SystemTime::now();
                    println!("File '{}' opened at: {:?}", FILE_PATH, current_time);
                }
            }
        }
        Err(e) => eprintln!("Error reading events: {}", e),
    }
}
