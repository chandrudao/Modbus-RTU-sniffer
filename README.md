# Modbus RTU Sniffer

A Python script to sniff Modbus RTU traffic over a serial port.

## Features
- Captures Modbus RTU frames from `/dev/ttyUSB0` (default).
- Supports functions: 1, 2, 3, 4, 5, 6, 15, 16.
- Shows requests/responses with timestamps, addresses, and data.
- Tracks starting addresses; handles missing devices.

## Requirements
- Python 3.x
- `pyserial` (`pip install pyserial`)
- Serial device (e.g., USB-to-RS485)

## Usage
1. Connect serial device.
2. Install: `pip install pyserial`
3. Run: `python Modbus_RTU_sniffer.py` or `chmod +x Modbus_RTU_sniffer.py && ./Modbus_RTU_sniffer.py`
4. Stop: `Ctrl+C`

## Configuration
Edit `Modbus_RTU_sniffer.py` top variables:
- `PORT = '/dev/ttyUSB0'` (e.g., `'COM3'` on Windows)
- `BAUD_RATE = 19200` (e.g., `9600`)
- `PARITY = serial.PARITY_EVEN` (e.g., `serial.PARITY_NONE`)
- `STOP_BITS = serial.STOPBITS_ONE` (e.g., `serial.STOPBITS_TWO`)
- `BYTE_SIZE = serial.EIGHTBITS` (e.g., `serial.SEVENBITS`)

## Example Output
```
Connected to /dev/ttyUSB0 at 19200 baud with even parity - Starting capture now...
Sniffing Modbus RTU traffic... (Ctrl+C to stop)

Packet: MODBUS Request (packet size: 8, data size: 4), 2025-02-14 05:31:50.510735 +0.000000
Mode: RTU Mode
Address: 1 (Slave)
Function: 3 (Read Holding Registers)
Starting Address: 2909
Quantity: 23
CRC: 12950 (OK)

Packet: MODBUS Response (packet size: 51, data size: 47), 2025-02-14 05:31:50.561177 +0.000000
Mode: RTU Mode
Address: 1 (Slave)
Function: 3 (Read Holding Registers)
Starting Address: 2909
Number of Registers: 23
Register Values:
Register0: 1543
Register1: 0
...
CRC: 10676 (OK)
