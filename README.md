<h1 align="center">
<br>
<img src=assets/ebpf-file-monitor.png height="400" border="2px solid #555">
<br>
<strong>Linux based File Monitoring using eBPF</strong>
</h1>

`ebpf-file-monitor` is a production-ready Rust program that provides comprehensive file monitoring with detailed event tracking, process information, and flexible output options.

## Features

### Core Monitoring
- **Comprehensive Event Tracking**: Monitors all file operations including:
  - ACCESS - File read operations
  - OPEN/CLOSE - File open and close events
  - MODIFY - Content modifications with size change tracking
  - CREATE/DELETE - File creation and deletion
  - MOVE/RENAME - File movement and renaming
  - ATTRIB - Attribute changes

### Data Collection
- **Process Information**: Captures PID, process name, command line, and user ID
- **Timestamp Precision**: Millisecond-precision timestamps in both human-readable and Unix formats
- **File Size Tracking**: Monitors file size changes with delta calculations
- **Graceful Shutdown**: Proper signal handling (Ctrl+C) with cleanup

### Output Options
- **Multiple Formats**: Text (human-readable) or JSON (machine-parsable)
- **File Logging**: Optional logging to file with append mode
- **Structured Data**: All events include comprehensive metadata

### Production Features
- **Error Handling**: Robust error handling for file system changes
- **Non-blocking**: Asynchronous operation prevents blocking on I/O
- **Resource Efficient**: Low overhead monitoring using inotify
- **Cross-platform**: Works on Linux (primary), with limited support for other platforms

## Prerequisites

- Rust 1.56+ (get the latest and greatest)
- Cargo (Rust's sweet package manager)  
- Any mainstream OS - Linux, Windows or MacOS
- libbpf and bcc libraries (eBPF's dynamic duo)

## Installation

```bash
# Clone this puppy 
git clone https://github.com/mranv/ebpf-file-monitor.git

# Hop into the directory
cd ebpf-file-monitor 

# Install bcc and libbpf if needed

# For Fedora/RedHat:
sudo yum install bcc bpf
# For Debian/Ubuntu:
sudo apt-get install libbpf-dev libbcc-dev

# Build  
cargo build --release
```

## Usage

### Command Line Options

```bash
ebpf-file-monitor [OPTIONS]

OPTIONS:
    -f, --file <FILE>           Path to the file to monitor
    -o, --output <FORMAT>       Output format: text or json (default: text)
    -l, --log-file <PATH>       Log events to file (optional)
    -v, --verbose               Enable verbose output
    -h, --help                  Print help information
    -V, --version               Print version information
```

### Basic Examples

```bash
# Monitor a file with text output
./target/release/ebpf-file-monitor --file /var/log/auth.log

# Monitor with JSON output
./target/release/ebpf-file-monitor --file /etc/passwd --output json

# Monitor and log to file
./target/release/ebpf-file-monitor -f /home/user/important.txt -l monitor.log

# Using environment variable
export EBPF_MONITOR_FILE=/path/to/your/file.txt
./target/release/ebpf-file-monitor
```

### Advanced Examples

```bash
# Monitor with JSON output and save to log file
./target/release/ebpf-file-monitor -f /var/log/syslog -o json -l events.json

# Verbose mode for debugging
./target/release/ebpf-file-monitor -f /tmp/test.txt -v

# Pipe JSON output to jq for processing
./target/release/ebpf-file-monitor -f /etc/hosts -o json | jq '.event_type'
```

### Sample Output

#### Text Format
```
[2025-07-31 10:15:23.456] MONITOR_START - /home/user/test.txt | Size: 1024 bytes | PID: 12345 (ebpf-file-monitor) | Details: File monitoring started
[2025-07-31 10:15:25.123] OPEN - /home/user/test.txt | Size: 1024 bytes | PID: 23456 (vim) | Details: File was opened
[2025-07-31 10:15:26.789] MODIFY - /home/user/test.txt | Size: 1536 bytes | PID: 23456 (vim) | Details: File content modified (size change: +512 bytes, new size: 1536 bytes)
[2025-07-31 10:15:27.012] CLOSE_WRITE - /home/user/test.txt | Size: 1536 bytes | PID: 23456 (vim) | Details: File closed after writing
```

#### JSON Format
```json
{
  "timestamp": "2025-07-31T10:15:26.789012345+00:00",
  "timestamp_unix": 1753928126,
  "event_type": "MODIFY",
  "file_path": "/home/user/test.txt",
  "file_size": 1536,
  "process_id": 23456,
  "process_name": "vim",
  "process_cmd": "vim /home/user/test.txt",
  "user_id": 1000,
  "details": "File content modified (size change: +512 bytes, new size: 1536 bytes)"
}
```

## Implementation

### Architecture
- **Event System**: Uses Linux inotify for efficient file system event monitoring
- **Async Runtime**: Built on Tokio for non-blocking I/O and concurrent operations
- **Process Info**: Leverages procfs to gather process metadata
- **Signal Handling**: Implements graceful shutdown with Ctrl+C handling
- **Error Recovery**: Continues monitoring even if individual events fail

### Event Types Monitored
- **ACCESS**: File read operations
- **OPEN**: File opened
- **CLOSE_WRITE**: File closed after modifications
- **CLOSE_NOWRITE**: File closed without modifications
- **MODIFY**: Content changes (tracks size differences)
- **CREATE**: File creation in watched directory
- **DELETE**: File deletion
- **MOVE**: File rename or move operations
- **ATTRIB**: Permission or attribute changes

## Use Cases

- **Security Monitoring**: Track access to sensitive files
- **Audit Logging**: Maintain compliance with file access logs
- **Development**: Debug file operations in applications
- **System Administration**: Monitor configuration file changes
- **Data Protection**: Track modifications to important documents

## Limitations

- Monitors single files (not directories recursively)
- Requires appropriate permissions for target files
- Process information limited to current process context
- inotify has system-wide limits on watches

## Contributions

Ideas to improve this little watchdog are welcome! Woof woof!
