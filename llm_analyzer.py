import os
import sys
import json
import requests
import time
import argparse
from pathlib import Path
from datetime import datetime

class OllamaConnector:
    """Handles connection and communication with Ollama LLM"""
    
    def __init__(self, model="codellama:7b-instruct", host="http://localhost:11434"):
        self.model = model
        self.host = host
        self.session = requests.Session()
        
    def test_connection(self):
        """Test if Ollama is running and model is available"""
        try:
            response = self.session.get(f"{self.host}/api/tags", timeout=5)
            if response.status_code != 200:
                return False, "Ollama server not responding"
            
            models = response.json().get("models", [])
            available_models = [model["name"] for model in models]
            
            if self.model not in available_models:
                return False, f"Model {self.model} not found. Available: {available_models}"
            
            return True, "Connection successful"
        except Exception as e:
            return False, f"Connection error: {str(e)}"
    
    def query_llm(self, prompt, max_tokens=2000):
        """Send a query to Ollama and get response"""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": 0.1,
                "top_p": 0.9
            }
        }
        
        try:
            response = self.session.post(
                f"{self.host}/api/generate",
                json=payload,
                timeout=120
            )
            
            if response.status_code == 200:
                result = response.json()
                return True, result.get("response", "").strip()
            else:
                return False, f"HTTP {response.status_code}: {response.text}"
                
        except requests.exceptions.Timeout:
            return False, "Request timed out (>2 minutes)"
        except Exception as e:
            return False, f"Request error: {str(e)}"

class DynamicVulnerabilityAnalyzer:
    """Dynamic vulnerability analyzer using LLM intelligence"""
    
    def __init__(self, llm_connector):
        self.llm = llm_connector
        
    def analyze_vulnerability(self, triage_data, source_code=None, binary_analysis=None):
        """Main analysis entry point - completely dynamic"""
        
        # Extract crash information
        if not triage_data.get("groups"):
            return {"error": "No crash groups found in triage data"}
        
        primary_crash = list(triage_data["groups"].items())[0]
        crash_frame, crash_info = primary_crash
        
        # Initialize result structure
        analysis_result = {
            "timestamp": datetime.now().isoformat(),
            "model_used": self.llm.model,
            "crash_frame": crash_frame,
            "crash_count": crash_info["count"],
            "vulnerability_classification": {},
            "dynamic_poc_generation": {},
            "dynamic_exploit_strategy": {},
            "source_code_analysis": {},
            "patch_recommendations": {}
        }
        
        print("Step 1: Dynamic vulnerability classification...")
        vuln_classification = self.classify_vulnerability(crash_frame, crash_info, source_code, binary_analysis)
        analysis_result["vulnerability_classification"] = vuln_classification
        
        print("Step 2: Generating vulnerability-specific PoC...")
        poc_generation = self.generate_dynamic_poc(crash_frame, crash_info, source_code, vuln_classification)
        analysis_result["dynamic_poc_generation"] = poc_generation
        
        print("Step 3: Creating exploit strategy...")
        exploit_strategy = self.generate_exploit_strategy(vuln_classification, binary_analysis, crash_info)
        analysis_result["dynamic_exploit_strategy"] = exploit_strategy
        
        if source_code:
            print("Step 4: Analyzing source code...")
            source_analysis = self.analyze_source_code(source_code, crash_frame)
            analysis_result["source_code_analysis"] = source_analysis
        
        print("Step 5: Generating patch recommendations...")
        patch_recommendations = self.generate_patches(source_code, vuln_classification)
        analysis_result["patch_recommendations"] = patch_recommendations
        
        return analysis_result
    
    def classify_vulnerability(self, crash_frame, crash_info, source_code, binary_analysis):
        """Dynamically classify vulnerability type using LLM"""
        
        # Build context for LLM
        context = f"""
CRASH ANALYSIS DATA:
- Crash Frame: {crash_frame}
- Number of crashes: {crash_info['count']}
- Sample crash file size: {crash_info['crashes'][0]['size']} bytes
"""
        
        if source_code:
            context += f"""
SOURCE CODE:
{source_code}
"""
        
        if binary_analysis:
            protections = binary_analysis.get('exploit_mitigation_summary', {})
            context += f"""
BINARY PROTECTIONS:
- Protection Level: {protections.get('protection_level', 'Unknown')}
- ASLR: {'Enabled' if binary_analysis.get('aslr_system', {}).get('enabled') else 'Disabled'}
- NX: {'Enabled' if binary_analysis.get('nx_bit', {}).get('enabled') else 'Disabled'}
- PIE: {'Enabled' if binary_analysis.get('pie', {}).get('enabled') else 'Disabled'}
- Stack Canaries: {'Enabled' if binary_analysis.get('stack_canaries', {}).get('enabled') else 'Disabled'}
"""
        
        prompt = f"""
You are a vulnerability research expert. Analyze this crash to determine the exact vulnerability type.

{context}

Classify this vulnerability as one of these types:
- stack_buffer_overflow: Classic stack-based buffer overflow
- heap_buffer_overflow: Heap-based buffer overflow
- format_string: Format string vulnerability (%n, %x, etc.)
- use_after_free: Use-after-free memory corruption
- double_free: Double free vulnerability
- command_injection: OS command injection
- sql_injection: SQL injection
- path_traversal: Directory traversal vulnerability
- integer_overflow: Integer overflow leading to corruption
- logic_bug: Business logic vulnerability
- memory_corruption_generic: Generic memory corruption
- unknown: Cannot determine specific type

Respond with ONLY this JSON format:
{{
    "vulnerability_type": "one_of_the_types_above",
    "confidence": 0.95,
    "reasoning": "detailed explanation of classification",
    "severity": "Critical/High/Medium/Low",
    "attack_vector": "how attacker triggers this",
    "impact": "what attacker can achieve",
    "technical_details": "technical explanation of vulnerability mechanism"
}}
"""
        
        success, response = self.llm.query_llm(prompt, max_tokens=1500)
        if not success:
            return {"error": f"LLM classification failed: {response}"}
        
        return self.extract_json_response(response)
    
    def generate_dynamic_poc(self, crash_frame, crash_info, source_code, vuln_classification):
        """Generate vulnerability-specific PoC using LLM"""
        
        vuln_type = vuln_classification.get('vulnerability_type', 'unknown')
        
        context = f"""
VULNERABILITY DETAILS:
- Type: {vuln_type}
- Crash Frame: {crash_frame}
- Crash Count: {crash_info['count']}
- Sample File Size: {crash_info['crashes'][0]['size']} bytes
"""
        
        if source_code:
            context += f"""
SOURCE CODE:
{source_code}
"""
        
        prompt = f"""
You are an expert exploit developer. Create a complete Python proof-of-concept script for this {vuln_type} vulnerability.

{context}

Requirements:
1. Generate a complete, working Python script
2. Make it specific to {vuln_type} (not generic buffer overflow)
3. The target binary takes a file as input argument
4. Include proper payload generation for this vulnerability type
5. Add debugging output and error handling
6. Make it self-contained and executable

Create the complete Python PoC script:
```python
#!/usr/bin/env python3
# [Your complete PoC code here]
```
"""
        
        success, response = self.llm.query_llm(prompt, max_tokens=3000)
        if not success:
            return {"error": f"PoC generation failed: {response}"}
        
        # Extract Python code
        code_start = response.find('```python')
        if code_start == -1:
            code_start = response.find('```')
        
        if code_start != -1:
            code_start = response.find('\n', code_start) + 1
            code_end = response.find('```', code_start)
            if code_end != -1:
                poc_code = response[code_start:code_end].strip()
                return {
                    "generated_successfully": True,
                    "vulnerability_type": vuln_type,
                    "poc_code": poc_code,
                    "description": f"Dynamic PoC for {vuln_type}"
                }
        
        return {
            "generated_successfully": False,
            "error": "Could not extract Python code from LLM response",
            "raw_response": response
        }
    
    def generate_exploit_strategy(self, vuln_classification, binary_analysis, crash_info):
        """Generate dynamic exploitation strategy using LLM"""
        
        vuln_type = vuln_classification.get('vulnerability_type', 'unknown')
        
        context = f"""
VULNERABILITY: {vuln_type}
TECHNICAL DETAILS: {vuln_classification.get('technical_details', 'Unknown')}
"""
        
        if binary_analysis:
            protections = binary_analysis.get('exploit_mitigation_summary', {})
            context += f"""
BINARY PROTECTIONS:
- Protection Level: {protections.get('protection_level', 'Unknown')}
- Required Bypass Techniques: {protections.get('required_techniques', [])}
- Vulnerable Areas: {protections.get('vulnerable_areas', [])}
"""
        
        prompt = f"""
You are an advanced exploit development expert. Create a comprehensive exploitation strategy for this {vuln_type} vulnerability.

{context}

Provide detailed strategy in this JSON format:
{{
    "exploitation_approach": "step-by-step approach description",
    "required_techniques": ["list", "of", "techniques"],
    "bypass_methods": ["methods", "for", "protection", "bypass"],
    "payload_strategy": "how to construct effective payload",
    "success_probability": "High/Medium/Low",
    "complexity": "Beginner/Intermediate/Advanced/Expert",
    "limitations": ["any", "limitations"],
    "alternative_approaches": ["other", "possible", "methods"]
}}
"""
        
        success, response = self.llm.query_llm(prompt, max_tokens=2000)
        if not success:
            return {"error": f"Strategy generation failed: {response}"}
        
        return self.extract_json_response(response)
    
    def analyze_source_code(self, source_code, crash_frame):
        """Analyze source code for vulnerabilities using LLM"""
        
        prompt = f"""
You are a security code reviewer. Analyze this source code for the vulnerability that caused this crash.

SOURCE CODE:
{source_code}

CRASH FRAME: {crash_frame}

Provide analysis in this JSON format:
{{
    "vulnerable_function": "function where vulnerability exists",
    "vulnerable_line": "specific line or description",
    "root_cause": "detailed explanation of vulnerability cause",
    "dangerous_functions": ["unsafe", "functions", "used"],
    "missing_protections": ["missing", "security", "measures"],
    "attack_surface": "how attacker reaches vulnerable code"
}}
"""
        
        success, response = self.llm.query_llm(prompt, max_tokens=1500)
        if not success:
            return {"error": f"Source analysis failed: {response}"}
        
        return self.extract_json_response(response)
    
    def generate_patches(self, source_code, vuln_classification):
        """Generate patch recommendations using LLM"""
        
        if not source_code:
            return {"error": "Source code not available for patch generation"}
        
        vuln_type = vuln_classification.get('vulnerability_type', 'unknown')
        
        prompt = f"""
You are a secure coding expert. Generate patches for this {vuln_type} vulnerability.

SOURCE CODE:
{source_code}

VULNERABILITY TYPE: {vuln_type}

Provide patches in this JSON format:
{{
    "immediate_fixes": ["critical", "fixes", "needed"],
    "secure_alternatives": {{"unsafe_function": "secure_replacement"}},
    "additional_protections": ["extra", "security", "measures"],
    "corrected_code_snippet": "fixed version of vulnerable code",
    "long_term_recommendations": ["architectural", "improvements"],
    "testing_recommendations": ["how", "to", "test", "fixes"]
}}
"""
        
        success, response = self.llm.query_llm(prompt, max_tokens=2000)
        if not success:
            return {"error": f"Patch generation failed: {response}"}
        
        return self.extract_json_response(response)
    
    def extract_json_response(self, response):
        """Extract JSON from LLM response"""
        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start != -1 and json_end != -1:
                json_text = response[json_start:json_end]
                return json.loads(json_text)
            else:
                return {"error": "No valid JSON found in response", "raw_response": response}
        except json.JSONDecodeError:
            return {"error": "Failed to parse JSON response", "raw_response": response}

def main():
    parser = argparse.ArgumentParser(description="LLM-powered dynamic vulnerability analysis")
    parser.add_argument("-t", "--triage-json", default="crash_triage.json",
                        help="Path to crash triage JSON file")
    parser.add_argument("-s", "--source-file", 
                        help="Path to source code file for analysis")
    parser.add_argument("-b", "--binary-analysis", default="binary_analysis.json",
                        help="Path to binary analysis JSON file")
    parser.add_argument("-o", "--output", default="llm_analysis.json",
                        help="Output file for LLM analysis results")
    parser.add_argument("-m", "--model", default="codellama:7b-instruct",
                        help="Ollama model to use for analysis")
    parser.add_argument("--host", default="http://localhost:11434",
                        help="Ollama server host")
    
    args = parser.parse_args()
    
    print("LLM-Powered Dynamic Vulnerability Analysis")
    print(f"Model: {args.model}")
    
    # Initialize LLM connection
    llm = OllamaConnector(model=args.model, host=args.host)
    
    # Test connection
    print("Testing Ollama connection...")
    success, message = llm.test_connection()
    if not success:
        print(f"Error: {message}")
        print("\nTo fix this, run:")
        print("   ollama pull codellama:7b-instruct")
        return 1
    
    print("Connection successful")
    
    # Load triage data
    if not os.path.exists(args.triage_json):
        print(f"Error: Triage file not found: {args.triage_json}")
        return 1
    
    with open(args.triage_json, 'r') as f:
        triage_data = json.load(f)
    
    # Load source code if provided
    source_code = None
    if args.source_file and os.path.exists(args.source_file):
        with open(args.source_file, 'r') as f:
            source_code = f.read()
        print(f"Loaded source code: {args.source_file}")
    
    # Load binary analysis if available
    binary_analysis = None
    if args.binary_analysis and os.path.exists(args.binary_analysis):
        with open(args.binary_analysis, 'r') as f:
            binary_analysis = json.load(f)
        print(f"Loaded binary analysis: {args.binary_analysis}")
    
    # Perform dynamic analysis
    analyzer = DynamicVulnerabilityAnalyzer(llm)
    print("\nStarting dynamic vulnerability analysis...")
    
    start_time = time.time()
    analysis_result = analyzer.analyze_vulnerability(triage_data, source_code, binary_analysis)
    analysis_time = time.time() - start_time
    
    analysis_result["analysis_duration_seconds"] = round(analysis_time, 2)
    
    # Save results
    with open(args.output, 'w') as f:
        json.dump(analysis_result, f, indent=2)
    
    print(f"\nAnalysis complete in {analysis_time:.1f} seconds")
    print(f"Results saved to: {args.output}")
    
    # Print summary
    print("\nDYNAMIC ANALYSIS SUMMARY")
    print("=" * 50)
    
    vuln = analysis_result.get("vulnerability_classification", {})
    if "vulnerability_type" in vuln and "error" not in vuln:
        print(f"Vulnerability Type: {vuln.get('vulnerability_type', 'Unknown')}")
        print(f"Severity: {vuln.get('severity', 'Unknown')}")
        print(f"Confidence: {vuln.get('confidence', 0):.1%}")
    
    poc = analysis_result.get("dynamic_poc_generation", {})
    if poc.get("generated_successfully"):
        print(f"PoC Generated: Yes (for {poc.get('vulnerability_type', 'Unknown')})")
    else:
        print("PoC Generated: No")
    
    exploit = analysis_result.get("dynamic_exploit_strategy", {})
    if "success_probability" in exploit and "error" not in exploit:
        print(f"Exploit Success Probability: {exploit.get('success_probability', 'Unknown')}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())