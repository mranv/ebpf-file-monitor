<h1 align="center">
<br>
<img src=assets/ebpf-file-monitor.png height="400" border="2px solid #555">
<br>
<strong>Linux based File Monitoring using eBPF</strong>
</h1>

`ebpf-file-monitor` is a slick Rust program that keeps an eagle-eye on your files and alerts you the moment changes occur!

## Features

- Uses cutting-edge eBPF technology to trace file events 
- Prints out a timestamp the instant your file is modified
- Works smoothly across Linux, Windows and MacOS

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

Update the `FILE_PATH` to the file you want to keep an eye on.

Let this watchdog loose:

```
./target/release/ebpf-file-monitor
```

Now it'll print a timestamp immediately when that file changes.

So you can catch co-workers messing with your stuff! Or track edits on your top secret novel.

## Implementation

- Uses libbpf to load sneaky eBPF programs that trace `open` and `write` syscalls.  
- Filters for events on your target file.
- When a modify event occurs, bam! prints the timestamp.
- eBPF + bcc = smooth cross-platform action.

## Limitations

- Watches only one file at a time.
- Needs eBPF/bcc libraries installed.

## Contributions

Ideas to improve this little watchdog are welcome! Woof woof!
