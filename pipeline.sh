set -e

TARGET_BINARY=${1:-"./target_binary"}
CRASHES_DIR="out/crashes"
MIN_CRASHES_DIR="out/crashes_min"
TRIAGE_JSON="crash_triage.json"
POC_OUTPUT="poc.py"

if [ ! -x "$TARGET_BINARY" ]; then
    echo "Error: Target binary $TARGET_BINARY not found or not executable"
    exit 1
fi

mkdir -p out
mkdir -p "$MIN_CRASHES_DIR"

echo "=== Step 1: Crash Minimization ==="
if [ ! -d "$CRASHES_DIR" ] || [ -z "$(ls -A $CRASHES_DIR 2>/dev/null)" ]; then
    echo "Error: No crashes found in $CRASHES_DIR"
    exit 1
fi

echo "Running minimization script..."
./minimize.sh "$TARGET_BINARY" "$CRASHES_DIR" "$MIN_CRASHES_DIR"

echo -e "\n=== Step 2: Crash Triage ==="
echo "Running triage script..."
CRASHES_DIR="$MIN_CRASHES_DIR" TARGET_BINARY="$TARGET_BINARY" OUTPUT_JSON="$TRIAGE_JSON" python3 triage.py

echo -e "\n=== Step 3: Generate Proof of Concept ==="
echo "Running PoC generator..."
python3 poc.py --target "$TARGET_BINARY" --triage-json "$TRIAGE_JSON" --output "$POC_OUTPUT"

echo -e "\n=== Step 4: Generate Crash Summary ==="
echo "Creating crash summary documentation..."
python3 - <<EOF
import json
import os
from datetime import datetime

# Load triage data
with open("$TRIAGE_JSON", "r") as f:
    triage_data = json.load(f)

# Create the summary markdown
with open("crash_summary.md", "w") as f:
    f.write("# AFL Crash Analysis Summary\n\n")
    f.write(f"**Target Binary:** `{os.path.basename('$TARGET_BINARY')}`  \n")
    f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n")
    f.write(f"**Total Crashes Analyzed:** {triage_data['total_crashes']}  \n")
    f.write(f"**Unique Crash Frames:** {triage_data['unique_crash_frames']}  \n\n")
    
    f.write("## Crash Groups\n\n")
    
    for i, (frame, data) in enumerate(triage_data["groups"].items()):
        f.write(f"### Group {i+1}: {frame}\n\n")
        f.write(f"**Count:** {data['count']} crashes  \n")
        f.write(f"**Representative File:** `{data['crashes'][0]['file']}`  \n")
        f.write(f"**File Size:** {data['crashes'][0]['size']} bytes  \n\n")
        
        if i == 0:
            f.write("**Selected for PoC:** Yes  \n")
            if os.path.exists("$POC_OUTPUT"):
                f.write(f"**PoC File:** [`{os.path.basename('$POC_OUTPUT')}`]({os.path.basename('$POC_OUTPUT')})  \n")
                with open("$POC_OUTPUT", "r") as poc_file:
                    poc_content = poc_file.read()
                    import re
                    offset_match = re.search(r"Identified crash offset: (\d+) bytes", poc_content)
                    if offset_match:
                        f.write(f"**Crash Offset:** {offset_match.group(1)} bytes  \n\n")
                    else:
                        f.write("**Crash Offset:** Unknown  \n\n")
            else:
                f.write("**PoC Status:** Generation failed  \n\n")
        else:
            f.write("**Selected for PoC:** No  \n\n")
            
        f.write("\n")
        
    f.write("## Next Steps\n\n")
    f.write("1. **Exploit Development:** Use the generated PoC as a starting point for developing a full exploit\n")
    f.write("2. **Root Cause Analysis:** Examine the specific code locations identified in the crash frames\n")
    f.write("3. **Patch Development:** Propose fixes for the identified vulnerabilities\n")

print(f"Crash summary created: crash_summary.md")
EOF

echo -e "\n=== Pipeline Complete ==="
echo "Summary file: crash_summary.md"
echo "PoC file: $POC_OUTPUT"

echo -e "\n=== Testing PoC ==="
if [ -x "$POC_OUTPUT" ]; then
    echo "Running PoC to verify crash reproduction..."
    python3 "$POC_OUTPUT"
else
    echo "PoC file not found or not executable"
fi