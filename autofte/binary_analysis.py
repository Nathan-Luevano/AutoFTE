"""Static binary protection analysis (NX, PIE, RELRO, canaries, ...).

Everything here shells out to standard binutils tools (readelf, objdump,
nm, ldd, file) plus the optional `checksec` script. Every external call
goes through `_run_tool` so missing tools, timeouts, and non-zero exits
are handled the same way everywhere instead of each check re-inventing
its own try/except.
"""

import os
import re
import subprocess
from datetime import datetime, timezone

TOOL_TIMEOUT_SECONDS = 15

DANGEROUS_FUNCTIONS = (
    "strcpy", "strcat", "sprintf", "vsprintf", "gets",
    "scanf", "strncpy", "strncat", "snprintf", "vsnprintf",
)

_ASLR_STATUS = {
    "0": "Disabled",
    "1": "Conservative (stack, heap, mmap, VDSO)",
    "2": "Full (includes data segments)",
}


def _run_tool(args):
    """Run an external tool and normalize the outcome.

    Returns (ok, stdout, error). `ok` is False for a missing binary, a
    timeout, or a non-zero exit -- callers don't need to special-case any
    of those individually.
    """
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=TOOL_TIMEOUT_SECONDS
        )
    except FileNotFoundError:
        return False, "", f"{args[0]} is not installed"
    except subprocess.TimeoutExpired:
        return False, "", f"{args[0]} timed out after {TOOL_TIMEOUT_SECONDS}s"

    if result.returncode != 0:
        error = result.stderr.strip() or f"{args[0]} exited {result.returncode}"
        return False, result.stdout, error

    return True, result.stdout, ""


class BinaryAnalyzer:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.protections = {}

    def analyze_all_protections(self):
        self.protections = {
            "binary_path": self.binary_path,
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "file_info": self._get_file_info(),
            "checksec": self._analyze_checksec(),
            "aslr_system": self._check_system_aslr(),
            "nx_bit": self._check_nx_bit(),
            "stack_canaries": self._check_stack_canaries(),
            "pie": self._check_pie(),
            "relro": self._check_relro(),
            "fortify": self._check_fortify(),
            "symbols": self._analyze_symbols(),
            "dynamic_libs": self._get_dynamic_libraries(),
        }
        self.protections["exploit_mitigation_summary"] = self._summarize_mitigations()
        return self.protections

    def _get_file_info(self):
        ok, stdout, error = _run_tool(["file", self.binary_path])
        if not ok:
            return {"error": error}

        file_output = stdout.strip()
        info = {
            "file_output": file_output,
            "architecture": "unknown",
            "format": "unknown",
            "stripped": "unknown",
        }

        if "x86-64" in file_output or "x86_64" in file_output:
            info["architecture"] = "x86_64"
        elif "i386" in file_output or "80386" in file_output:
            info["architecture"] = "i386"
        elif "ARM" in file_output:
            info["architecture"] = "ARM"

        if "ELF" in file_output:
            info["format"] = "ELF"
        elif "PE32" in file_output:
            info["format"] = "PE"

        if "not stripped" in file_output:
            info["stripped"] = False
        elif "stripped" in file_output:
            info["stripped"] = True

        return info

    def _analyze_checksec(self):
        ok, stdout, error = _run_tool(["checksec", "--file", self.binary_path])
        if not ok:
            return {"checksec_available": False, "error": error}
        return {"checksec_output": stdout.strip()}

    def _check_system_aslr(self):
        proc_path = "/proc/sys/kernel/randomize_va_space"
        if not os.path.exists(proc_path):
            return {"status": "Cannot determine (non-Linux system)"}

        try:
            with open(proc_path, encoding="utf-8") as handle:
                aslr_value = handle.read().strip()
        except OSError as exc:
            return {"error": str(exc)}

        return {
            "value": aslr_value,
            "status": _ASLR_STATUS.get(aslr_value, "Unknown"),
            "enabled": aslr_value != "0",
        }

    def _check_nx_bit(self):
        ok, stdout, error = _run_tool(["readelf", "-l", self.binary_path])
        if not ok:
            return {"error": error}

        # readelf -l wraps each program header across two lines: the
        # GNU_STACK line itself, then a continuation line that carries the
        # RWE/RW permission flags. Both have to be read together.
        nx_enabled = False
        stack_info = ""
        lines = stdout.split("\n")
        for i, line in enumerate(lines):
            if "GNU_STACK" in line:
                continuation = lines[i + 1] if i + 1 < len(lines) else ""
                stack_info = f"{line.strip()} {continuation.strip()}"
                nx_enabled = "RWE" not in continuation
                break

        return {
            "enabled": nx_enabled,
            "stack_info": stack_info,
            "description": "NX bit prevents execution of stack/heap data",
        }

    def _check_stack_canaries(self):
        ok, stdout, error = _run_tool(["objdump", "-t", self.binary_path])
        if not ok:
            return {"error": error}

        canary_symbols = ["__stack_chk_fail", "__stack_chk_guard"]
        found_symbols = [symbol for symbol in canary_symbols if symbol in stdout]

        related_strings = []
        strings_ok, strings_out, _ = _run_tool(["strings", self.binary_path])
        if strings_ok:
            for line in strings_out.split("\n"):
                lowered = line.lower()
                if "stack" in lowered and ("smash" in lowered or "guard" in lowered):
                    related_strings.append(line.strip())

        return {
            "enabled": len(found_symbols) > 0,
            "symbols_found": found_symbols,
            "related_strings": related_strings,
            "description": "Stack canaries detect buffer overflows",
        }

    def _check_pie(self):
        ok, stdout, error = _run_tool(["readelf", "-h", self.binary_path])
        if not ok:
            return {"error": error}

        pie_enabled = False
        file_type = ""
        for line in stdout.split("\n"):
            if "Type:" in line:
                file_type = line.strip()
                pie_enabled = "DYN" in line
                break

        return {
            "enabled": pie_enabled,
            "file_type": file_type,
            "description": "PIE randomizes base address of executable",
        }

    def _check_relro(self):
        ok, stdout, error = _run_tool(["readelf", "-l", self.binary_path])
        if not ok:
            return {"error": error}

        has_gnu_relro = "GNU_RELRO" in stdout

        has_bind_now = False
        dynamic_ok, dynamic_out, _ = _run_tool(["readelf", "-d", self.binary_path])
        if dynamic_ok:
            has_bind_now = "BIND_NOW" in dynamic_out

        if has_gnu_relro and has_bind_now:
            relro_status = "Full RELRO"
        elif has_gnu_relro:
            relro_status = "Partial RELRO"
        else:
            relro_status = "No RELRO"

        return {
            "status": relro_status,
            "gnu_relro": has_gnu_relro,
            "bind_now": has_bind_now,
            "description": "RELRO makes GOT read-only after linking",
        }

    def _check_fortify(self):
        ok, stdout, error = _run_tool(["objdump", "-t", self.binary_path])
        if not ok:
            return {"error": error}

        # \b at the end matters: without it this also partial-matches
        # __stack_chk_fail as "__stack_chk" and misreports a canary
        # symbol as a FORTIFY_SOURCE function.
        fortified_functions = sorted(set(re.findall(r"__\w+_chk\b", stdout)))
        return {
            "enabled": len(fortified_functions) > 0,
            "fortified_functions": fortified_functions,
            "description": "FORTIFY_SOURCE adds runtime checks to dangerous functions",
        }

    def _analyze_symbols(self):
        ok, stdout, error = _run_tool(["nm", "-D", self.binary_path])
        if not ok:
            return {"error": error}

        found_dangerous = []
        imported_functions = []
        for line in stdout.split("\n"):
            parts = line.split()
            # nm -D leaves the address column blank for undefined dynamic
            # symbols, so most lines are "U <name>" (2 fields), not
            # "<addr> U <name>" (3 fields) -- only locally-defined exports
            # carry an address.
            if len(parts) == 2 and parts[0] == "U":
                raw_name = parts[1]
            elif len(parts) >= 3 and parts[1] == "U":
                raw_name = parts[2]
            else:
                continue

            # Versioned symbols look like "strcpy@GLIBC_2.2.5"; compare
            # against the bare name.
            func_name = raw_name.split("@")[0]
            imported_functions.append(func_name)
            if func_name in DANGEROUS_FUNCTIONS:
                found_dangerous.append(func_name)

        return {
            "dangerous_functions_found": found_dangerous,
            "total_imported_functions": len(imported_functions),
            "sample_imports": imported_functions[:10],
        }

    def _get_dynamic_libraries(self):
        ok, stdout, error = _run_tool(["ldd", self.binary_path])
        if not ok:
            return {"error": error, "libraries": [], "count": 0}

        libraries = [line.strip() for line in stdout.split("\n") if "=>" in line]
        return {"libraries": libraries, "count": len(libraries)}

    def _summarize_mitigations(self):
        techniques = []
        vulnerable_areas = []
        protection_count = 0

        if self.protections.get("aslr_system", {}).get("enabled"):
            protection_count += 1
            techniques.append("ASLR bypass (info leak required)")
        else:
            vulnerable_areas.append("ASLR disabled - fixed addresses")

        if self.protections.get("nx_bit", {}).get("enabled"):
            protection_count += 1
            techniques.append("NX bypass (ROP/JOP required)")
        else:
            vulnerable_areas.append("NX disabled - shellcode execution possible")

        if self.protections.get("stack_canaries", {}).get("enabled"):
            protection_count += 1
            techniques.append("Stack canary bypass (leak or bruteforce)")
        else:
            vulnerable_areas.append("No stack canaries - direct buffer overflow")

        if self.protections.get("pie", {}).get("enabled"):
            protection_count += 1
            techniques.append("PIE bypass (code base leak required)")
        else:
            vulnerable_areas.append("No PIE - fixed code addresses")

        relro_status = self.protections.get("relro", {}).get("status", "")
        if relro_status == "Full RELRO":
            protection_count += 1
            techniques.append("GOT overwrite not possible")
        elif relro_status == "Partial RELRO":
            protection_count += 0.5
            techniques.append("Limited GOT overwrite possible")
        else:
            vulnerable_areas.append("No RELRO - GOT overwrite possible")

        if protection_count >= 4:
            protection_level, exploit_difficulty = "High", "Hard"
        elif protection_count >= 2:
            protection_level, exploit_difficulty = "Medium", "Medium"
        else:
            protection_level, exploit_difficulty = "Low", "Easy"

        return {
            "protection_level": protection_level,
            "exploit_difficulty": exploit_difficulty,
            "protection_count": protection_count,
            "required_techniques": techniques,
            "vulnerable_areas": vulnerable_areas,
            "recommended_approach": self._recommend_approach(techniques),
        }

    @staticmethod
    def _recommend_approach(techniques):
        if not techniques:
            return "Direct exploitation possible - minimal protections"

        steps = []
        if "NX bypass (ROP/JOP required)" in techniques:
            steps.append("Build ROP chain for code execution")
        if "ASLR bypass (info leak required)" in techniques:
            steps.append("Find information leak to defeat ASLR")
        if "Stack canary bypass (leak or bruteforce)" in techniques:
            steps.append("Leak or bruteforce stack canary")
        if "PIE bypass (code base leak required)" in techniques:
            steps.append("Leak code base address for PIE bypass")

        return " -> ".join(steps) if steps else "Standard buffer overflow exploitation"


def analyze_binary(binary_path):
    """Convenience wrapper: run every check and return the finished dict."""
    analyzer = BinaryAnalyzer(binary_path)
    return analyzer.analyze_all_protections()
