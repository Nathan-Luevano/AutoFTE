TARGET_BINARY=${1:-"./target"}

if [ ! -x "$TARGET_BINARY" ]; then
    echo "Error: Target binary $TARGET_BINARY not found or not executable"
    echo "Usage: $0 [target_binary]"
    exit 1
fi

echo "Binary Protection Analyzer"
echo "Target: $TARGET_BINARY"
echo ""

echo "Running binary protection analysis..."
python3 binary_analyzer.py "$TARGET_BINARY" --verbose

echo ""
echo "Results saved to: binary_analysis.json"
echo ""

if [ -f "binary_analysis.json" ]; then
    echo "Protection Summary:"
    python3 -c "
import json
with open('binary_analysis.json', 'r') as f:
    data = json.load(f)

summary = data.get('exploit_mitigation_summary', {})
print(f'Protection Level: {summary.get(\"protection_level\", \"Unknown\")}')
print(f'Exploit Difficulty: {summary.get(\"exploit_difficulty\", \"Unknown\")}')

if summary.get('required_techniques'):
    print('\\nBypass Techniques Needed:')
    for technique in summary['required_techniques']:
        print(f'  - {technique}')

if summary.get('vulnerable_areas'):
    print('\\nVulnerable Areas:')
    for area in summary['vulnerable_areas']:
        print(f'  - {area}')
"
fi