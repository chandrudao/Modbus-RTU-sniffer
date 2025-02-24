#!/usr/bin/env python3
# Modbus_RTU_sniffer.py - A Python script to sniff and analyze Modbus RTU traffic
#
# Copyright (C) 2025 [Chandru]
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import serial
import time
from datetime import datetime
from threading import Thread
from queue import Queue

# Serial port settings
PORT = '/dev/ttyUSB0'
BAUD_RATE = 19200
PARITY = serial.PARITY_EVEN
STOP_BITS = serial.STOPBITS_ONE
BYTE_SIZE = serial.EIGHTBITS

# Store recent requests to match with responses
recent_requests = {}  # (address, function) -> starting_address

# Open the serial port
try:
    ser = serial.Serial(
        port=PORT,
        baudrate=BAUD_RATE,
        parity=PARITY,
        stopbits=STOP_BITS,
        bytesize=BYTE_SIZE,
        timeout=0.1
    )
    print(f"Connected to {PORT} at {BAUD_RATE} baud with even parity - Starting capture now...")
except serial.SerialException as e:
    print(f"Failed to connect to {PORT}: {e}")
    exit(1)

# Modbus RTU CRC-16 calculation
def calculate_crc(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc

# Parse and print a frame
def print_frame(frame):
    if len(frame) < 4:
        return
    
    crc = calculate_crc(frame[:-2])
    crc_bytes = frame[-2:]
    if crc != (crc_bytes[1] << 8 | crc_bytes[0]):
        return

    addr = frame[0]
    func = frame[1]
    packet_size = len(frame)
    data_size = packet_size - 4
    ts_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
    
    func_desc = {
        1: "Read Coils",
        2: "Read Discrete Inputs",
        3: "Read Holding Registers",
        4: "Read Input Registers",
        5: "Write Single Coil",
        6: "Write Single Register",
        15: "Write Multiple Coils",
        16: "Write Multiple Registers"
    }.get(func, f"Unknown Function {func}")
    
    is_request = (
        (func in [1, 2, 3, 4] and packet_size == 8) or
        (func in [5, 6] and packet_size == 6) or
        (func in [15, 16] and packet_size >= 9)
    )
    packet_type = "Request" if is_request else "Response"

    print(f"\nPacket: MODBUS {packet_type} (packet size: {packet_size}, data size: {data_size}), {ts_str} +0.000000")
    print("Mode: RTU Mode")
    print(f"Address: {addr} (Slave)")
    print(f"Function: {func} ({func_desc})")

    if is_request:
        if func in [1, 2, 3, 4]:
            start_addr = (frame[2] << 8) + frame[3]
            quantity = (frame[4] << 8) + frame[5]
            recent_requests[(addr, func)] = start_addr
            print(f"Starting Address: {start_addr}")
            print(f"Quantity: {quantity}")
        elif func in [5, 6]:
            reg_addr = (frame[2] << 8) + frame[3]
            value = (frame[4] << 8) + frame[5]
            recent_requests[(addr, func)] = reg_addr
            print(f"Starting Address: {reg_addr}")
            print(f"Value: {value}")
        elif func in [15, 16]:
            start_addr = (frame[2] << 8) + frame[3]
            reg_count = (frame[4] << 8) + frame[5]
            byte_count = frame[6]
            recent_requests[(addr, func)] = start_addr
            print(f"Starting Address: {start_addr}")
            print(f"Number of Registers: {reg_count}")
            if len(frame) >= 7 + byte_count:
                print("Values:")
                if func == 15:
                    for i in range(reg_count):
                        byte_idx = 7 + (i // 8)
                        bit_idx = i % 8
                        if byte_idx < len(frame) - 2:
                            value = (frame[byte_idx] >> bit_idx) & 1
                            print(f"Coil{i}: {value}")
                elif func == 16:
                    for i in range(reg_count):
                        reg_val = (frame[7 + i*2] << 8) + frame[8 + i*2]
                        print(f"Register{i}: {reg_val}")
    else:
        start_addr = recent_requests.get((addr, func), "[Unknown]")
        if func == 3 and len(frame) > 5:
            byte_count = frame[2]
            reg_count = byte_count // 2
            print(f"Starting Address: {start_addr}")
            print(f"Number of Registers: {reg_count}")
            print("Register Values:")
            for i in range(reg_count):
                reg_val = (frame[3 + i*2] << 8) + frame[4 + i*2]
                print(f"Register{i}: {reg_val}")
        elif func in [1, 2, 4] and len(frame) > 5:
            byte_count = frame[2]
            print(f"Starting Address: {start_addr}")
            if func in [1, 2]:
                quantity = byte_count * 8
                print(f"Quantity: {quantity}")
                print("Values:")
                for i in range(byte_count):
                    for bit in range(8):
                        if (i * 8 + bit) < quantity:
                            value = (frame[3 + i] >> bit) & 1
                            print(f"{'Coil' if func == 1 else 'Input'}{i*8 + bit}: {value}")
            elif func == 4:
                reg_count = byte_count // 2
                print(f"Number of Registers: {reg_count}")
                print("Values:")
                for i in range(reg_count):
                    reg_val = (frame[3 + i*2] << 8) + frame[4 + i*2]
                    print(f"Register{i}: {reg_val}")
        elif func in [5, 6, 15, 16]:
            start_addr = (frame[2] << 8) + frame[3]
            value_or_count = (frame[4] << 8) + frame[5]
            print(f"Starting Address: {start_addr}")
            print(f"{'Value' if func in [5, 6] else 'Quantity'}: {value_or_count}")

    print(f"CRC: {crc} (OK)")

# Data collection thread
def collect_data(queue):
    buffer = bytearray()
    while True:
        data = ser.read(ser.in_waiting or 1)
        if data:
            buffer.extend(data)
            start = 0
            while start < len(buffer) - 3:
                frame_end = None
                for end in range(start + 4, len(buffer) + 1):
                    possible_frame = buffer[start:end]
                    if len(possible_frame) >= 4:
                        crc = calculate_crc(possible_frame[:-2])
                        crc_bytes = possible_frame[-2:]
                        if crc == (crc_bytes[1] << 8 | crc_bytes[0]):
                            frame_end = end
                            break
                if frame_end:
                    frame = buffer[start:frame_end]
                    queue.put(bytes(frame))
                    start = frame_end
                else:
                    break
            if start > 0:
                buffer = buffer[start:]
            if len(buffer) > 1000:
                buffer = bytearray()
        time.sleep(0.0001)

# Data processing thread
def process_data(queue):
    print("Sniffing Modbus RTU traffic... (Ctrl+C to stop)")
    while True:
        if not queue.empty():
            frame = queue.get()
            print_frame(frame)
            queue.task_done()
        time.sleep(0.001)

# Main execution
data_queue = Queue()
collector = Thread(target=collect_data, args=(data_queue,), daemon=True)
processor = Thread(target=process_data, args=(data_queue,), daemon=True)

try:
    collector.start()
    processor.start()
    collector.join()
except KeyboardInterrupt:
    print("\nStopped by user")
finally:
    ser.close()
    print("Serial port closed")
