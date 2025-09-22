# Flipper Zero BLE Sniffer

Flipper Zero app that captures BLE packets via nRF52840 and saves them as PCAP files.

## Hardware Setup

Connect nRF52840 to Flipper Zero:

| nRF52840 | Flipper Zero | Function |
|----------|--------------|----------|
| GND      | GND          | Ground   |
| 3.3V     | 3.3V         | Power    |
| P0.06    | A14 (RX)     | Data TX  |
| P0.08    | A13 (TX)     | Data RX  |

## Software Setup

### nRF52840 Setup
1. Flash nRF Sniffer firmware to nRF52840
2. Firmware outputs BLE packets via UART at 115200 baud

### Build Flipper App
```bash
# Using ufbt (recommended)
python -m ufbt APPDIR=. APPID=ble_sniffer build

# Or using make
make build
```

### Install on Flipper
1. Copy `ble_sniffer.fap` to `/ext/apps/Tools/`
2. Launch from Apps > Tools > BLE Sniffer

## Usage

- **OK**: Start/Stop capture
- **Back**: Exit
- **Left**: Pause
- **Right**: New file

Files saved as `ble_capture_*.pcap` on SD card.

## Current Status

✅ Basic UI and file management  
🚧 UART communication (in progress)  
🚧 PCAP generation (planned)

## License

MIT License
