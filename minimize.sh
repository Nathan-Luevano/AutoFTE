set -e

TARGET_BINARY=${1:-"./target_binary"}  
CRASHES_DIR=${2:-"out/crashes"}        
MIN_CRASHES_DIR=${3:-"out/crashes_min"}

mkdir -p "$MIN_CRASHES_DIR"

if ! command -v afl-cmin &> /dev/null; then
    echo "Error: afl-cmin not found. Please ensure AFL is installed and in your PATH."
    exit 1
fi

if [ ! -x "$TARGET_BINARY" ]; then
    echo "Error: Target binary $TARGET_BINARY not found or not executable."
    exit 1
fi

if [ ! -d "$CRASHES_DIR" ]; then
    echo "Error: Crashes directory $CRASHES_DIR not found."
    exit 1
fi

INITIAL_COUNT=$(find "$CRASHES_DIR" -type f -not -name "README.txt" | wc -l)
echo "Found $INITIAL_COUNT raw crash files in $CRASHES_DIR"

echo "Starting crash minimization process..."
afl-cmin -i "$CRASHES_DIR" -o "$MIN_CRASHES_DIR" -t 5000 -- "$TARGET_BINARY" @@

FINAL_COUNT=$(find "$MIN_CRASHES_DIR" -type f -not -name "README.txt" | wc -l)
echo "Minimization complete. Reduced $INITIAL_COUNT crashes to $FINAL_COUNT unique crashes."
echo "Minimized crashes saved to $MIN_CRASHES_DIR"