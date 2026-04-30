# CAN Intrusion Detection System (IDS) Toolkit

A lightweight C++17 library and CLI for simulating AUTOSAR-aligned CAN Intrusion Detection. Provides whitelist-based ID/DLC validation, frequency monitoring, and anomaly blocking without external dependencies.

## Features
- Whitelist-based CAN ID filtering (default-deny policy)
- DLC validation for Classic CAN & CAN FD
- Frame frequency/rate monitoring (anti-flood)
- Payload length validation
- Thread-safe rule management & statistics
- Pure C++17 + STL (zero external dependencies)
- Interactive CLI for testing and HIL validation

## Prerequisites
- C++17 Compiler (GCC 11+ / Clang 14+)
- CMake 3.16+ & Ninja

## Build & Run
```bash
git clone 
cd can-ids-toolkit
mkdir build && cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
ninja
./can_ids_cli
```

## Usage Examples
```bash
# Enable IDS
enable

# Add rule: ID 0x123, allow DLCs 0,4,8, min 50ms interval
add id=0x123 dlc=0,4,8 interval=50

# Start monitoring
monitor

# Simulate frames
simulate 123#DEADBEEF        # PASS
simulate 123#AA              # BLOCK (Invalid DLC)
simulate 456#AABBCCDD        # BLOCK (Unauthorized ID)

# View stats
stats
```
## AUTOSAR Compliance Notes

## License
MIT License. See LICENSE for details.