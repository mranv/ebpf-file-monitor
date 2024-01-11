Here is the fixed table of contents:

# ebpf-file-monitor

`ebpf-file-monitor` is a Rust program that monitors file modifications using the inotify API. This utility allows users to track changes in a specified file and prints a timestamp when modifications occur.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)

## Introduction

This program monitors a specified file for changes using inotify on Linux. It prints a message when the file is modified. 

## Code Overview

- An `Inotify` instance is created to interface with inotify.

- A watch is added for the target file for `MODIFY` events.

- An infinite loop runs which:

  - Calls `handle_events` to handle any events synchronously.

  - Sleeps for the monitoring interval.

- `handle_events` reads any pending events into a buffer.

- The buffer is iterated through looking for `MODIFY` events.

- If a modify event is found, the current time is printed.

## Example Output

```
File '/home/user/file.txt' opened at: 2022-07-19T19:32:58.927315500+00:00
```

## Dependencies

- `inotify` crate

- `tokio` crate

## Features

- **File Monitoring:** Tracks modifications in the specified file.

- **Timestamp Logging:** Prints a timestamp when the file is modified.
  
## Getting Started

Install all the following prerequisites

### Prerequisites

- Rust 1.56+

- Cargo

- Linux OS (for inotify)

- eBPF

- bcc

- build-essentials

### Installation

Provide step-by-step instructions on how to install your project. Include any commands or configuration needed to set it up.

```bash
# Clone the repository
git clone https://github.com/mranv/ebpf-file-monitor.git

# Navigate to the project directory 
cd ebpf-file-monitor

# Build the project
cargo build --release
```

## Usage 

The file path to monitor and the monitoring interval can be configured by modifying the `FILE_PATH` and `MONITOR_INTERVAL_SECONDS` constants.

The program must be run on Linux as it relies on inotify.

Simply follow the below steps.

```bash
# Run the compiled binary
./target/release/ebpf-file-monitor  
```

Let me know if you need any other changes to the table of contents!
