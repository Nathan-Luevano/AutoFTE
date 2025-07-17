import os
import sys
import json
import subprocess
import argparse
import re
from pathlib import Path
from datetime import datetime

class BinaryAnalyzer:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.protections = {}
        
    def analyze_all_protections(self):
        """Run all protection analysis checks"""
        print("Starting binary protection analysis...")
        
        self.protections = {
            "binary_path": self.binary_path,
            "analysis_timestamp": datetime.now().isoformat(),
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
            "exploit_mitigation_summary": self._summarize_mitigations()
        }
        
        return self.protections
    
    def _get_file_info(self):
        """Get basic file information"""
        try:
            result = subprocess.run(['file', self.binary_path], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                file_output = result.stdout.strip()
                
                info = {
                    "file_output": file_output,
                    "architecture": "unknown",
                    "format": "unknown",
                    "stripped": "unknown"
                }
                
                # Parse architecture
                if "x86-64" in file_output or "x86_64" in file_output:
                    info["architecture"] = "x86_64"
                elif "i386" in file_output or "80386" in file_output:
                    info["architecture"] = "i386"
                elif "ARM" in file_output:
                    info["architecture"] = "ARM"
                
                # Parse format
                if "ELF" in file_output:
                    info["format"] = "ELF"
                elif "PE32" in file_output:
                    info["format"] = "PE"
                
                # Check if stripped
                if "stripped" in file_output:
                    info["stripped"] = True
                elif "not stripped" in file_output:
                    info["stripped"] = False
                
                return info
            else:
                return {"error": "Could not analyze file"}
        except Exception as e:
            return {"error": str(e)}
    
    def _analyze_checksec(self):
        """Use checksec if available for comprehensive analysis"""
        try:
            result = subprocess.run(['checksec', '--file', self.binary_path], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return {"checksec_output": result.stdout.strip()}
            else:
                return {"checksec_available": False}
        except FileNotFoundError:
            return {"checksec_available": False}
        except Exception as e:
            return {"error": str(e)}
    
    def _check_system_aslr(self):
        """Check system-wide ASLR settings"""
        try:
            if os.path.exists('/proc/sys/kernel/randomize_va_space'):
                with open('/proc/sys/kernel/randomize_va_space', 'r') as f:
                    aslr_value = f.read().strip()
                    
                    aslr_status = {
                        "0": "Disabled",
                        "1": "Conservative (stack, heap, mmap, VDSO)",
                        "2": "Full (includes data segments)"
                    }
                    
                    return {
                        "value": aslr_value,
                        "status": aslr_status.get(aslr_value, "Unknown"),
                        "enabled": aslr_value != "0"
                    }
            else:
                return {"status": "Cannot determine (non-Linux system)"}
        except Exception as e:
            return {"error": str(e)}
    
    def _check_nx_bit(self):
        """Check for NX/DEP protection using readelf"""
        try:
            result = subprocess.run(['readelf', '-l', self.binary_path], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                output = result.stdout
                
                # Look for GNU_STACK segment
                nx_enabled = False
                stack_info = ""
                
                lines = output.split('\n')
                for i, line in enumerate(lines):
                    if 'GNU_STACK' in line:
                        stack_info = line.strip()
                        # Check if stack is executable (RWE vs RW)
                        if 'RWE' in line:
                            nx_enabled = False
                        elif 'RW' in line:
                            nx_enabled = True
                        break
                
                return {
                    "enabled": nx_enabled,
                    "stack_info": stack_info,
                    "description": "NX bit prevents execution of stack/heap data"
                }
            else:
                return {"error": "Could not analyze with readelf"}
        except FileNotFoundError:
            return {"error": "readelf not available"}
        except Exception as e:
            return {"error": str(e)}
    
    def _check_stack_canaries(self):
        """Check for stack canary protection"""
        try:
            # Method 1: Check for __stack_chk_fail symbol
            result = subprocess.run(['objdump', '-t', self.binary_path], 
                                  capture_output=True, text=True)
            
            canary_symbols = ['__stack_chk_fail', '__stack_chk_guard']
            found_symbols = []
            
            if result.returncode == 0:
                for symbol in canary_symbols:
                    if symbol in result.stdout:
                        found_symbols.append(symbol)
            
            # Method 2: Check strings for canary-related strings
            strings_result = subprocess.run(['strings', self.binary_path], 
                                          capture_output=True, text=True)
            
            canary_strings = []
            if strings_result.returncode == 0:
                for line in strings_result.stdout.split('\n'):
                    if 'stack' in line.lower() and ('smash' in line.lower() or 'guard' in line.lower()):
                        canary_strings.append(line.strip())
            
            enabled = len(found_symbols) > 0
            
            return {
                "enabled": enabled,
                "symbols_found": found_symbols,
                "related_strings": canary_strings,
                "description": "Stack canaries detect buffer overflows"
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def _check_pie(self):
        """Check for Position Independent Executable"""
        try:
            result = subprocess.run(['readelf', '-h', self.binary_path], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                output = result.stdout
                
                # Look for file type
                pie_enabled = False
                file_type = ""
                
                for line in output.split('\n'):
                    if 'Type:' in line:
                        file_type = line.strip()
                        if 'DYN' in line:
                            pie_enabled = True
                        elif 'EXEC' in line:
                            pie_enabled = False
                        break
                
                return {
                    "enabled": pie_enabled,
                    "file_type": file_type,
                    "description": "PIE randomizes base address of executable"
                }
            else:
                return {"error": "Could not analyze with readelf"}
        except Exception as e:
            return {"error": str(e)}
    
    def _check_relro(self):
        """Check for RELRO (RELocation Read-Only) protection"""
        try:
            result = subprocess.run(['readelf', '-l', self.binary_path], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                output = result.stdout
                
                has_gnu_relro = 'GNU_RELRO' in output
                
                # Check for BIND_NOW in dynamic section
                dynamic_result = subprocess.run(['readelf', '-d', self.binary_path], 
                                              capture_output=True, text=True)
                
                has_bind_now = False
                if dynamic_result.returncode == 0:
                    has_bind_now = 'BIND_NOW' in dynamic_result.stdout
                
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
                    "description": "RELRO makes GOT read-only after linking"
                }
            else:
                return {"error": "Could not analyze with readelf"}
        except Exception as e:
            return {"error": str(e)}
    
    def _check_fortify(self):
        """Check for FORTIFY_SOURCE protection"""
        try:
            result = subprocess.run(['objdump', '-t', self.binary_path], 
                                  capture_output=True, text=True)
            
            fortified_functions = []
            if result.returncode == 0:
                # Look for _chk variants of functions
                fortify_patterns = [
                    r'__\w+_chk',  # __strcpy_chk, __memcpy_chk, etc.
                ]
                
                for pattern in fortify_patterns:
                    matches = re.findall(pattern, result.stdout)
                    fortified_functions.extend(matches)
            
            return {
                "enabled": len(fortified_functions) > 0,
                "fortified_functions": list(set(fortified_functions)),
                "description": "FORTIFY_SOURCE adds runtime checks to dangerous functions"
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def _analyze_symbols(self):
        """Analyze symbol table for security-relevant information"""
        try:
            result = subprocess.run(['nm', '-D', self.binary_path], 
                                  capture_output=True, text=True)
            
            dangerous_functions = [
                'strcpy', 'strcat', 'sprintf', 'vsprintf', 'gets',
                'scanf', 'strncpy', 'strncat', 'snprintf', 'vsnprintf'
            ]
            
            found_dangerous = []
            imported_functions = []
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3 and parts[1] == 'U':  # Undefined symbol (imported)
                            func_name = parts[2]
                            imported_functions.append(func_name)
                            if func_name in dangerous_functions:
                                found_dangerous.append(func_name)
            
            return {
                "dangerous_functions_found": found_dangerous,
                "total_imported_functions": len(imported_functions),
                "sample_imports": imported_functions[:10]  # First 10 for brevity
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def _get_dynamic_libraries(self):
        """Get list of dynamically linked libraries"""
        try:
            result = subprocess.run(['ldd', self.binary_path], 
                                  capture_output=True, text=True)
            
            libraries = []
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if '=>' in line:
                        lib_info = line.strip()
                        libraries.append(lib_info)
            
            return {
                "libraries": libraries,
                "count": len(libraries)
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def _summarize_mitigations(self):
        """Provide a summary of exploit mitigations and bypass techniques"""
        summary = {
            "protection_level": "unknown",
            "exploit_difficulty": "unknown",
            "required_techniques": [],
            "vulnerable_areas": []
        }
        
        # This will be populated after all other checks are done
        # We'll update this in the analyze_all_protections method
        return summary
    
    def update_mitigation_summary(self):
        """Update the mitigation summary based on analysis results"""
        techniques = []
        vulnerable_areas = []
        protection_count = 0
        
        # Check each protection and determine bypass requirements
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
        if "Full RELRO" in relro_status:
            protection_count += 1
            techniques.append("GOT overwrite not possible")
        elif "Partial RELRO" in relro_status:
            protection_count += 0.5
            techniques.append("Limited GOT overwrite possible")
        else:
            vulnerable_areas.append("No RELRO - GOT overwrite possible")
        
        # Determine overall protection level
        if protection_count >= 4:
            protection_level = "High"
            exploit_difficulty = "Hard"
        elif protection_count >= 2:
            protection_level = "Medium"
            exploit_difficulty = "Medium"
        else:
            protection_level = "Low"
            exploit_difficulty = "Easy"
        
        self.protections["exploit_mitigation_summary"] = {
            "protection_level": protection_level,
            "exploit_difficulty": exploit_difficulty,
            "protection_count": protection_count,
            "required_techniques": techniques,
            "vulnerable_areas": vulnerable_areas,
            "recommended_approach": self._get_recommended_approach(techniques, vulnerable_areas)
        }
    
    def _get_recommended_approach(self, techniques, vulnerable_areas):
        """Recommend exploitation approach based on protections"""
        if not techniques:
            return "Direct exploitation possible - minimal protections"
        
        approach = []
        
        if "NX bypass (ROP/JOP required)" in techniques:
            approach.append("Build ROP chain for code execution")
        
        if "ASLR bypass (info leak required)" in techniques:
            approach.append("Find information leak to defeat ASLR")
        
        if "Stack canary bypass (leak or bruteforce)" in techniques:
            approach.append("Leak or bruteforce stack canary")
        
        if "PIE bypass (code base leak required)" in techniques:
            approach.append("Leak code base address for PIE bypass")
        
        if not approach:
            approach = ["Standard buffer overflow exploitation"]
        
        return " -> ".join(approach)

def main():
    parser = argparse.ArgumentParser(description="Binary protection analysis")
    parser.add_argument("binary", help="Path to binary to analyze")
    parser.add_argument("-o", "--output", default="binary_analysis.json",
                        help="Output file for analysis results")
    parser.add_argument("--verbose", action="store_true",
                        help="Verbose output")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.binary):
        print(f"Error: Binary file '{args.binary}' not found")
        return 1
    
    print(f"Analyzing binary protections: {args.binary}")
    
    analyzer = BinaryAnalyzer(args.binary)
    results = analyzer.analyze_all_protections()
    
    # Update the mitigation summary with calculated values
    analyzer.update_mitigation_summary()
    
    # Save results to JSON
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"Analysis complete. Results saved to: {args.output}")
    
    # Print summary
    print("\nBINARY PROTECTION SUMMARY")
    print("=" * 50)
    
    summary = results.get("exploit_mitigation_summary", {})
    print(f"Protection Level: {summary.get('protection_level', 'Unknown')}")
    print(f"Exploit Difficulty: {summary.get('exploit_difficulty', 'Unknown')}")
    
    print(f"\nProtections Detected:")
    print(f"  ASLR: {'Enabled' if results.get('aslr_system', {}).get('enabled') else 'Disabled'}")
    print(f"  NX Bit: {'Enabled' if results.get('nx_bit', {}).get('enabled') else 'Disabled'}")
    print(f"  Stack Canaries: {'Enabled' if results.get('stack_canaries', {}).get('enabled') else 'Disabled'}")
    print(f"  PIE: {'Enabled' if results.get('pie', {}).get('enabled') else 'Disabled'}")
    print(f"  RELRO: {results.get('relro', {}).get('status', 'Unknown')}")
    
    if summary.get('required_techniques'):
        print(f"\nRequired Bypass Techniques:")
        for technique in summary['required_techniques']:
            print(f"  - {technique}")
    
    if summary.get('vulnerable_areas'):
        print(f"\nVulnerable Areas:")
        for area in summary['vulnerable_areas']:
            print(f"  - {area}")
    
    if summary.get('recommended_approach'):
        print(f"\nRecommended Approach:")
        print(f"  {summary['recommended_approach']}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())