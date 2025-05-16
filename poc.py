import os
import sys
import json
import subprocess
import argparse
import string
import random
from pathlib import Path

def create_parser():
    parser = argparse.ArgumentParser(description="Generate a Proof of Concept for a crash")
    parser.add_argument("-t", "--target", default="./target_binary", 
                        help="Path to the target binary")
    parser.add_argument("-c", "--crash-file", 
                        help="Path to a representative crash file")
    parser.add_argument("-f", "--frame", 
                        help="Use a specific crash frame from the triage output")
    parser.add_argument("-j", "--triage-json", default="crash_triage.json",
                        help="Path to the triage JSON output")
    parser.add_argument("-o", "--output", default="poc.py",
                        help="Output PoC file name")
    parser.add_argument("-s", "--start-size", type=int, default=16,
                        help="Starting size for payload testing")
    parser.add_argument("-m", "--max-size", type=int, default=1024,
                        help="Maximum payload size to try")
    parser.add_argument("-p", "--pattern", action="store_true",
                        help="Use a cyclic pattern instead of 'A's")
    return parser

def load_triage_data(triage_json):
    """Load the triage output JSON file"""
    if not os.path.exists(triage_json):
        print(f"Error: Triage data file {triage_json} not found")
        return None
    
    with open(triage_json, 'r') as f:
        return json.load(f)

def select_crash(triage_data, frame=None):
    """Select a crash from the triage data based on the frame or the most common crash"""
    if not triage_data or "groups" not in triage_data:
        return None, None
    
    if frame and frame in triage_data["groups"]:
        selected_frame = frame
    else:
        selected_frame = list(triage_data["groups"].keys())[0]
    
    crashes = triage_data["groups"][selected_frame]["crashes"]
    if not crashes:
        return None, None
    
    return selected_frame, crashes[0]["path"]

def generate_pattern(length):
    """Generate a non-repeating pattern for offset finding"""
    alphabet = string.ascii_lowercase
    
    def pattern_gen():
        for x in alphabet:
            for y in alphabet:
                for z in alphabet:
                    yield x + y + z
    
    pattern = ''
    for chunk in pattern_gen():
        pattern += chunk
        if len(pattern) >= length:
            break
    
    return pattern[:length]

def test_payload(target_binary, payload_size, use_pattern=False):
    """Test a payload of given size against the target and check if it crashes"""
    if use_pattern:
        payload = generate_pattern(payload_size).encode()
    else:
        payload = b"A" * payload_size
    
    try:
        result = subprocess.run(
            [target_binary],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        return False, result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, -1, b"TIMEOUT", b""
    except subprocess.CalledProcessError as e:
        return True, e.returncode, e.stdout, e.stderr

def find_crash_offset(target_binary, start_size, max_size, use_pattern=False):
    """Find the smallest payload size that causes a crash"""
    print("Searching for crash offset...")
    
    low = start_size
    high = max_size
    
    crashed, code, stdout, stderr = test_payload(target_binary, low, use_pattern)
    if crashed:
        print(f"Initial size {low} already causes a crash (exit code {code})")
        return low, stdout, stderr
    
    crashed, code, stdout, stderr = test_payload(target_binary, high, use_pattern)
    if not crashed:
        print(f"Even at maximum size {high}, no crash detected")
        return None, None, None
    
    smallest_crashing = high
    smallest_stdout = stdout
    smallest_stderr = stderr
    
    while low <= high:
        mid = (low + high) // 2
        crashed, code, stdout, stderr = test_payload(target_binary, mid, use_pattern)
        
        if crashed:
            smallest_crashing = min(smallest_crashing, mid)
            smallest_stdout = stdout
            smallest_stderr = stderr
            high = mid - 1
        else:
            low = mid + 1
    
    return smallest_crashing, smallest_stdout, smallest_stderr

def generate_poc_script(target_binary, offset, output_file, crash_file, frame, use_pattern=False):
    """Generate a PoC Python script that reproduces the crash"""
    target_name = os.path.basename(target_binary)
    
    with open(output_file, "w") as f:
        f.write(f'''#!/usr/bin/env python3
# Crash Proof of Concept for {target_name}
# Generated automatically by poc.py

import sys
import subprocess
import os

# Target crash frame: {frame}
# Original crash file: {os.path.basename(crash_file)}
# Identified crash offset: {offset} bytes

# Path to the target binary
TARGET = "{target_binary}"

def main():
    # Ensure target exists
    if not os.path.exists(TARGET):
        print(f"Error: Target binary {{TARGET}} not found")
        return 1
        
    # Create the payload
    payload_size = {offset}
    {"payload = generate_pattern(payload_size)" if use_pattern else "payload = b'A' * payload_size"}
    
    print(f"Sending payload of {{payload_size}} bytes to {{TARGET}}...")
    
    try:
        # Launch the process and feed it our payload
        process = subprocess.Popen(
            [TARGET], 
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        stdout, stderr = process.communicate(payload)
        exit_code = process.returncode
        
        # Check if we crashed the program
        if exit_code != 0:
            print(f"Success! Process crashed with exit code {{exit_code}}")
            if stdout:
                print("\\nProgram output:")
                print(stdout.decode('utf-8', errors='replace'))
            if stderr:
                print("\\nError output:")
                print(stderr.decode('utf-8', errors='replace'))
            return 0
        else:
            print("Failed: Process did not crash")
            return 1
            
    except Exception as e:
        print(f"Error executing payload: {{e}}")
        return 1

"""
def generate_pattern(length):
    # Generate a non-repeating pattern for offset finding
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    
    def pattern_gen():
        for x in alphabet:
            for y in alphabet:
                for z in alphabet:
                    yield x + y + z
    
    pattern = b''
    for chunk in pattern_gen():
        pattern += chunk.encode()
        if len(pattern) >= length:
            break
    
    return pattern[:length]
""" if use_pattern else ""

if __name__ == "__main__":
    sys.exit(main())
''')
    
    os.chmod(output_file, 0o755)
    print(f"PoC script generated: {output_file}")

def main():
    parser = create_parser()
    args = parser.parse_args()
    
    target_binary = args.target
    if not os.path.exists(target_binary) or not os.access(target_binary, os.X_OK):
        print(f"Error: Target binary {target_binary} not found or not executable")
        return 1
    
    crash_file = args.crash_file
    frame = args.frame
    
    if not crash_file:
        triage_data = load_triage_data(args.triage_json)
        if not triage_data:
            print("Error: Could not load triage data and no crash file specified")
            return 1
        
        selected_frame, selected_crash = select_crash(triage_data, frame)
        if not selected_crash:
            print("Error: Could not select a crash from triage data")
            return 1
        
        crash_file = selected_crash
        frame = selected_frame
    
    if not os.path.exists(crash_file):
        print(f"Error: Crash file {crash_file} not found")
        return 1
    
    if not frame:
        frame = "Unknown crash frame"
    
    print(f"Target binary: {target_binary}")
    print(f"Selected crash: {crash_file}")
    print(f"Selected frame: {frame}")
    
    offset, stdout, stderr = find_crash_offset(
        target_binary, 
        args.start_size, 
        args.max_size,
        args.pattern
    )
    
    if offset:
        print(f"Found crash at offset: {offset} bytes")
        generate_poc_script(
            target_binary, 
            offset, 
            args.output, 
            crash_file, 
            frame,
            args.pattern
        )
        return 0
    else:
        print("Failed to find crash offset")
        return 1

if __name__ == "__main__":
    sys.exit(main())