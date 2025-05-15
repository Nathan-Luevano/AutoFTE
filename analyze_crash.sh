RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' 

print_banner() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║               ${YELLOW}FUZZING CRASH ANALYZER${BLUE}                   ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
}

print_section() {
    echo -e "\n${CYAN}┌─────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│ ${MAGENTA}$1${CYAN}${NC}"
    echo -e "${CYAN}└─────────────────────────────────────────────────────┘${NC}"
}

if [ $# -eq 0 ]; then
    print_banner
    echo -e "\n${YELLOW}[*] No crash file specified, looking for the most recent crash...${NC}"
    
    CRASH_DIRS=("out/default/crashes" "out/crashes" "crashes" "findings/crashes")
    
    for dir in "${CRASH_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            CRASH_FILE=$(find "$dir" -type f -name "id*" -not -name "README.txt" 2>/dev/null | sort -r | head -n 1)
            if [ -n "$CRASH_FILE" ]; then
                echo -e "${GREEN}[+] Found crash in $dir directory${NC}"
                break
            fi
        fi
    done
    
    if [ -z "$CRASH_FILE" ]; then
        echo -e "${RED}[!] Error: No crash files found in any of the standard directories${NC}"
        echo -e "${YELLOW}[*] Please specify a crash file path as an argument${NC}"
        exit 1
    fi
else
    CRASH_FILE="$1"
    if [ ! -f "$CRASH_FILE" ]; then
        echo -e "${RED}[!] Error: Specified crash file '$CRASH_FILE' does not exist${NC}"
        exit 1
    fi
    print_banner
fi

is_binary() {
    if [ -z "$(file "$1" | grep text)" ]; then
        return 0  
    else
        return 1  
    fi
}

print_section "CRASH FILE INFORMATION"
echo -e "${GREEN}Crash file:${NC} $CRASH_FILE"
SIZE=$(stat --printf="%s" "$CRASH_FILE" 2>/dev/null || stat -f "%z" "$CRASH_FILE")
echo -e "${GREEN}File size:${NC} $SIZE bytes"
echo -e "${GREEN}Created:${NC} $(stat --printf="%y" "$CRASH_FILE" 2>/dev/null || stat -f "%Sm" "$CRASH_FILE")"
echo -e "${GREEN}File type:${NC} $(file -b "$CRASH_FILE")"

print_section "CRASH INPUT PREVIEW"
if is_binary "$CRASH_FILE"; then
    echo -e "${YELLOW}Binary content detected. Showing hexdump:${NC}\n"
    hexdump -C "$CRASH_FILE" | head -n 10
    
    if [ $SIZE -gt 160 ]; then
        echo -e "${YELLOW}... (file truncated, showing first 160 bytes only) ...${NC}"
    fi
    
    NON_PRINTABLE=$(tr -d '[:print:]' < "$CRASH_FILE" | wc -c)
    echo -e "\n${GREEN}Non-printable characters:${NC} $NON_PRINTABLE bytes ($(echo "scale=1; $NON_PRINTABLE*100/$SIZE" | bc)% of file)"
else
    echo -e "${YELLOW}Text content detected. Showing first 10 lines:${NC}\n"
    head -n 10 "$CRASH_FILE"
    
    if [ $(wc -l < "$CRASH_FILE") -gt 10 ]; then
        echo -e "${YELLOW}... (file truncated, showing first 10 lines only) ...${NC}"
    fi
    
    LINES=$(wc -l < "$CRASH_FILE")
    echo -e "\n${GREEN}Lines:${NC} $LINES"
fi

print_section "PATTERN ANALYSIS"
if grep -q "AAAAAAAA" "$CRASH_FILE"; then
    echo -e "${YELLOW}[*] File contains 'A' patterns - possible buffer overflow testing${NC}"
fi

if grep -q "%n%n%n" "$CRASH_FILE"; then
    echo -e "${YELLOW}[*] File contains format string patterns (%n) - possible format string attack${NC}"
fi

if xxd -p "$CRASH_FILE" | grep -q "90909090"; then
    echo -e "${YELLOW}[*] File contains NOP sleds - possible shellcode/exploitation attempt${NC}"
fi

print_section "REPEATING PATTERNS"
echo -e "${GREEN}Top 3 most common byte sequences (4-byte):${NC}"
xxd -p "$CRASH_FILE" | tr -d '\n' | grep -o '.\{8\}' | sort | uniq -c | sort -nr | head -3 | while read count pattern; do
    if [ "$count" -gt 1 ]; then
        hex_pattern=$(echo $pattern | sed 's/\(..\)/\\x\1/g')
        echo -e "$count occurrences: $pattern (hex: $hex_pattern)"
    fi
done

print_section "NEXT STEPS"
echo -e "1. ${GREEN}Run with GDB:${NC}"
echo -e "   \$ gdb -q ./target"
echo -e "   (gdb) run < $CRASH_FILE"
echo -e "\n2. ${GREEN}Try with ASAN:${NC}"
echo -e "   \$ afl-gcc -fsanitize=address -o target_asan vuln.c"
echo -e "   \$ ./target_asan $CRASH_FILE"
echo -e "\n3. ${GREEN}Determine crash offset:${NC}"
echo -e "   \$ ./find_offset.py $CRASH_FILE"

echo -e "\n${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║               ${YELLOW}ANALYSIS COMPLETE${BLUE}                        ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"