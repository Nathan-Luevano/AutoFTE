import os
import sys
import json
import subprocess
import re
from collections import defaultdict

CRASHES_DIR = os.environ.get("CRASHES_DIR", "out/default/crashes")
TARGET_BINARY = os.environ.get("TARGET_BINARY", "./target")
OUTPUT_JSON = os.environ.get("OUTPUT_JSON", "crash_triage.json")
DEBUGGER = os.environ.get("DEBUGGER", "gdb")  

def run_debugger(binary, crash_file):
    """Run the binary under the debugger with the crash file as input and extract backtrace"""
    if DEBUGGER == "gdb":
        gdb_commands = [
            f"run {crash_file}",
            "bt 10",  
            "quit"
        ]
        
        cmd = [
            "gdb", 
            "--batch",  
            "--quiet",  
            "--return-child-result",  
            "--ex", "set pagination off",  
            f"--args", binary
        ]
        
        for gdb_cmd in gdb_commands:
            cmd.extend(["--ex", gdb_cmd])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return "TIMEOUT", "Process timed out after 10 seconds"
    else:
        raise NotImplementedError(f"Debugger {DEBUGGER} not yet supported")

def extract_crash_frame(stdout, stderr):
    """Extract the most relevant stack frame from debugger output"""
    if "TIMEOUT" in stdout:
        return "TIMEOUT"
    
    frame_pattern = r'#(\d+)\s+0x([0-9a-f]+) in ([^\s]+) (?:\([^)]*\) )?(?:at ([^:]+):(\d+))?'
    frames = re.findall(frame_pattern, stdout)
    
    if not frames:
        if "SIGSEGV" in stdout or "Segmentation fault" in stdout:
            addr_match = re.search(r'0x([0-9a-f]+) in (\w+)', stdout)
            if addr_match:
                addr, func = addr_match.groups()
                return f"SIGSEGV at 0x{addr} in {func}"
            return "SIGSEGV (stack corruption)"
        elif "SIGABRT" in stdout:
            return "SIGABRT (abort signal)"
        return "UNKNOWN_CRASH"
    
    frame = frames[0]
    frame_num, addr, func, file, line = frame
    if file and line:
        return f"#{frame_num} 0x{addr} in {func} at {file}:{line}"
    else:
        return f"#{frame_num} 0x{addr} in {func}"

def triage_crashes():
    """Process all crash files and group them by their crash stack frame"""
    if not os.path.exists(CRASHES_DIR):
        print(f"Error: Crashes directory {CRASHES_DIR} not found")
        return None
    
    if not os.path.exists(TARGET_BINARY) or not os.access(TARGET_BINARY, os.X_OK):
        print(f"Error: Target binary {TARGET_BINARY} not found or not executable")
        return None
    
    crash_files = [f for f in os.listdir(CRASHES_DIR) 
                  if os.path.isfile(os.path.join(CRASHES_DIR, f)) and f != "README.txt"]
    
    if not crash_files:
        print(f"No crash files found in {CRASHES_DIR}")
        return {}
    
    print(f"Triaging {len(crash_files)} crash files...")
    
    crash_groups = defaultdict(list)
    
    for idx, crash_file in enumerate(crash_files):
        crash_path = os.path.join(CRASHES_DIR, crash_file)
        print(f"Processing {idx+1}/{len(crash_files)}: {crash_file}", end="\r")
        
        stdout, stderr = run_debugger(TARGET_BINARY, crash_path)
        crash_frame = extract_crash_frame(stdout, stderr)
        
        crash_groups[crash_frame].append({
            "file": crash_file, 
            "path": crash_path,
            "size": os.path.getsize(crash_path)
        })
    
    print("\nTriage complete")
    
    sorted_groups = {k: v for k, v in sorted(
        crash_groups.items(), 
        key=lambda item: len(item[1]), 
        reverse=True
    )}
    
    result = {
        "total_crashes": len(crash_files),
        "unique_crash_frames": len(sorted_groups),
        "groups": {}
    }
    
    for frame, crashes in sorted_groups.items():
        result["groups"][frame] = {
            "count": len(crashes),
            "crashes": sorted(crashes, key=lambda x: x["size"])
        }
    
    return result

def main():
    """Main function to triage crashes and output results"""
    print(f"Crash Triage Tool - Processing directory: {CRASHES_DIR}")
    print(f"Target binary: {TARGET_BINARY}")
    
    triage_result = triage_crashes()
    if not triage_result:
        return 1
    
    with open(OUTPUT_JSON, 'w') as f:
        json.dump(triage_result, f, indent=2)
    
    print("\n=== Crash Triage Summary ===")
    print(f"Total crashes analyzed: {triage_result['total_crashes']}")
    print(f"Unique crash frames found: {triage_result['unique_crash_frames']}")
    print("\nTop crash locations:")
    
    for i, (frame, data) in enumerate(list(triage_result["groups"].items())[:5]):
        print(f"{i+1}. {frame} - {data['count']} crashes")
        print(f"   Sample crash file: {data['crashes'][0]['file']}")
    
    print(f"\nFull results saved to {OUTPUT_JSON}")
    return 0

if __name__ == "__main__":
    sys.exit(main())