use std::path::PathBuf;
use std::time::SystemTime;

use inotify::{Inotify, WatchMask, EventMask, WatchDescriptor};
use tokio::time::{sleep, Duration};

const FILE_PATH: &str = "/home/mranv/Desktop/ebpf-file-monitor/example.txt";
const MONITOR_INTERVAL_SECONDS: u64 = 1;

#[tokio::main]
async fn main() {
  let mut inotify = Inotify::init().expect("Failed to initialize inotify");  

  let watch_descriptor = inotify
    .watches()
    .add(PathBuf::from(FILE_PATH), WatchMask::ACCESS)
    .expect("Failed to add watch");

  loop {
    handle_events(&mut inotify, &watch_descriptor).await;

    sleep(Duration::from_secs(MONITOR_INTERVAL_SECONDS)).await;
  }
}

async fn handle_events(inotify: &mut Inotify, _watch_descriptor: &WatchDescriptor) {
  
  let mut buffer = [0u8; 4096];

  match inotify.read_events_blocking(&mut buffer) {
    Ok(events) => {
      for event in events {
        if event.mask.contains(EventMask::ACCESS) {
          let now = SystemTime::now();
          println!("File '{}' accessed at: {:?}", FILE_PATH, now);
        }  
      }
    }
    Err(e) => eprintln!("Error reading events: {}", e),
  }
}