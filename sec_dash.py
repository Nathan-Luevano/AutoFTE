#!/usr/bin/env python3
"""
Professional Security Dashboard Generator
Creates a sleek Flask web dashboard for Red Team Automation Suite results
"""

import os
import json
import sys
import shutil
from datetime import datetime
from pathlib import Path

def create_dashboard_structure():
    """Create the Flask app directory structure"""
    
    dashboard_dir = "security_dashboard"
    
    # Remove existing dashboard
    if os.path.exists(dashboard_dir):
        shutil.rmtree(dashboard_dir)
    
    # Create directory structure
    dirs = [
        f"{dashboard_dir}",
        f"{dashboard_dir}/templates",
        f"{dashboard_dir}/static",
        f"{dashboard_dir}/static/css",
        f"{dashboard_dir}/static/js",
        f"{dashboard_dir}/data"
    ]
    
    for dir_path in dirs:
        os.makedirs(dir_path, exist_ok=True)
    
    return dashboard_dir

def create_flask_app(dashboard_dir):
    """Create the main Flask application"""
    
    app_code = '''#!/usr/bin/env python3
"""
Red Team Automation Suite - Security Dashboard
Professional web interface for vulnerability analysis results
"""

from flask import Flask, render_template, jsonify, send_from_directory
import json
import os
from datetime import datetime
import markdown

app = Flask(__name__)

def load_json_data(filename):
    """Load JSON data with error handling"""
    try:
        if os.path.exists(f"data/{filename}"):
            with open(f"data/{filename}", 'r') as f:
                return json.load(f)
    except:
        pass
    return {}

def load_markdown_report():
    """Load and convert markdown report"""
    try:
        if os.path.exists("data/comprehensive_security_report.md"):
            with open("data/comprehensive_security_report.md", 'r') as f:
                content = f.read()
                return markdown.markdown(content, extensions=['tables', 'fenced_code', 'toc'])
    except:
        pass
    return "<p>Report not available</p>"

@app.route('/')
def dashboard():
    """Main dashboard view"""
    
    # Load all analysis data
    triage_data = load_json_data('crash_triage.json')
    binary_data = load_json_data('binary_analysis.json')
    llm_data = load_json_data('llm_analysis.json')
    
    # Calculate metrics
    metrics = calculate_metrics(triage_data, binary_data, llm_data)
    
    return render_template('dashboard.html', 
                         metrics=metrics,
                         triage_data=triage_data,
                         binary_data=binary_data,
                         llm_data=llm_data)

@app.route('/report')
def report():
    """Detailed markdown report view"""
    report_html = load_markdown_report()
    return render_template('report.html', report_content=report_html)

@app.route('/technical')
def technical():
    """Technical data view"""
    triage_data = load_json_data('crash_triage.json')
    binary_data = load_json_data('binary_analysis.json')
    llm_data = load_json_data('llm_analysis.json')
    
    return render_template('technical.html',
                         triage_data=triage_data,
                         binary_data=binary_data,
                         llm_data=llm_data)

@app.route('/exploits')
def exploits():
    """Generated exploits view"""
    
    # Check for generated files
    poc_exists = os.path.exists('../poc.py')
    advanced_exists = os.path.exists('../advanced_exploit.py')
    mythic_exists = os.path.exists('../mythic_output')
    
    return render_template('exploits.html',
                         poc_exists=poc_exists,
                         advanced_exists=advanced_exists,
                         mythic_exists=mythic_exists)

@app.route('/api/metrics')
def api_metrics():
    """API endpoint for metrics data"""
    triage_data = load_json_data('crash_triage.json')
    binary_data = load_json_data('binary_analysis.json')
    llm_data = load_json_data('llm_analysis.json')
    
    metrics = calculate_metrics(triage_data, binary_data, llm_data)
    return jsonify(metrics)

@app.route('/download/<filename>')
def download_file(filename):
    """Download generated files"""
    return send_from_directory('../', filename, as_attachment=True)

def calculate_metrics(triage_data, binary_data, llm_data):
    """Calculate dashboard metrics"""
    
    # Basic metrics
    total_crashes = triage_data.get('total_crashes', 0)
    unique_frames = triage_data.get('unique_crash_frames', 0)
    
    # Vulnerability info
    vuln_info = llm_data.get('vulnerability_classification', {})
    vuln_type = vuln_info.get('vulnerability_type', 'Unknown')
    severity = vuln_info.get('severity', 'Unknown')
    confidence = vuln_info.get('confidence', 0)
    
    # Protection info
    protections = binary_data.get('exploit_mitigation_summary', {})
    protection_level = protections.get('protection_level', 'Unknown')
    exploit_difficulty = protections.get('exploit_difficulty', 'Unknown')
    
    # AI Analysis status
    poc_generated = llm_data.get('dynamic_poc_generation', {}).get('generated_successfully', False)
    strategy_available = bool(llm_data.get('dynamic_exploit_strategy', {}))
    
    return {
        'total_crashes': total_crashes,
        'unique_frames': unique_frames,
        'vulnerability_type': vuln_type,
        'severity': severity,
        'confidence': round(confidence * 100) if isinstance(confidence, float) else confidence,
        'protection_level': protection_level,
        'exploit_difficulty': exploit_difficulty,
        'poc_generated': poc_generated,
        'strategy_available': strategy_available,
        'analysis_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

if __name__ == '__main__':
    print("Red Team Automation Suite - Security Dashboard")
    print("=" * 50)
    print("Starting dashboard server...")
    print("Access your results at: http://localhost:5000")
    print("Features:")
    print("   • Executive Dashboard")
    print("   • Technical Analysis")
    print("   • Generated Exploits")
    print("   • Comprehensive Report")
    print("   • Download Artifacts")
    print()
    print("Press Ctrl+C to stop the server")
    print("=" * 50)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
'''
    
    with open(f"{dashboard_dir}/app.py", 'w') as f:
        f.write(app_code)
    
    os.chmod(f"{dashboard_dir}/app.py", 0o755)

def create_dashboard_template(dashboard_dir):
    """Create the main dashboard HTML template"""
    
    template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Red Team Automation Suite - Security Dashboard</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="{{ url_for('static', filename='css/dashboard.css') }}" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
</head>
<body>
    <div class="dashboard-container">
        <!-- Header -->
        <header class="dashboard-header">
            <div class="header-content">
                <h1><i class="fas fa-shield-alt"></i> Red Team Automation Suite</h1>
                <p>Professional Security Analysis Dashboard</p>
            </div>
            <nav class="dashboard-nav">
                <a href="/" class="nav-item active"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
                <a href="/report" class="nav-item"><i class="fas fa-file-alt"></i> Report</a>
                <a href="/technical" class="nav-item"><i class="fas fa-code"></i> Technical</a>
                <a href="/exploits" class="nav-item"><i class="fas fa-bug"></i> Exploits</a>
            </nav>
        </header>

        <!-- Main Content -->
        <main class="dashboard-main">
            
            <!-- Key Metrics -->
            <section class="metrics-grid">
                <div class="metric-card vulnerability">
                    <div class="metric-icon">
                        <i class="fas fa-exclamation-triangle"></i>
                    </div>
                    <div class="metric-content">
                        <h3>{{ metrics.vulnerability_type }}</h3>
                        <p>Vulnerability Type</p>
                        <div class="severity-badge severity-{{ metrics.severity.lower() }}">{{ metrics.severity }}</div>
                    </div>
                </div>

                <div class="metric-card crashes">
                    <div class="metric-icon">
                        <i class="fas fa-bomb"></i>
                    </div>
                    <div class="metric-content">
                        <h3>{{ metrics.total_crashes }}</h3>
                        <p>Total Crashes</p>
                        <span class="metric-sub">{{ metrics.unique_frames }} unique frames</span>
                    </div>
                </div>

                <div class="metric-card confidence">
                    <div class="metric-icon">
                        <i class="fas fa-brain"></i>
                    </div>
                    <div class="metric-content">
                        <h3>{{ metrics.confidence }}%</h3>
                        <p>AI Confidence</p>
                        <div class="confidence-bar">
                            <div class="confidence-fill" style="width: {{ metrics.confidence }}%"></div>
                        </div>
                    </div>
                </div>

                <div class="metric-card protection">
                    <div class="metric-icon">
                        <i class="fas fa-shield"></i>
                    </div>
                    <div class="metric-content">
                        <h3>{{ metrics.protection_level }}</h3>
                        <p>Protection Level</p>
                        <span class="metric-sub">{{ metrics.exploit_difficulty }} to exploit</span>
                    </div>
                </div>
            </section>

            <!-- Analysis Overview -->
            <section class="analysis-grid">
                <div class="analysis-card">
                    <h3><i class="fas fa-chart-pie"></i> Analysis Overview</h3>
                    <canvas id="analysisChart" width="400" height="200"></canvas>
                </div>

                <div class="analysis-card">
                    <h3><i class="fas fa-cogs"></i> AI Generation Status</h3>
                    <div class="status-list">
                        <div class="status-item">
                            <i class="fas fa-{{ 'check' if metrics.poc_generated else 'times' }} status-{{ 'success' if metrics.poc_generated else 'error' }}"></i>
                            <span>Dynamic PoC Generated</span>
                        </div>
                        <div class="status-item">
                            <i class="fas fa-{{ 'check' if metrics.strategy_available else 'times' }} status-{{ 'success' if metrics.strategy_available else 'error' }}"></i>
                            <span>Exploit Strategy Available</span>
                        </div>
                        {% if llm_data.get('source_code_analysis') %}
                        <div class="status-item">
                            <i class="fas fa-check status-success"></i>
                            <span>Source Code Analyzed</span>
                        </div>
                        {% endif %}
                        {% if llm_data.get('patch_recommendations') %}
                        <div class="status-item">
                            <i class="fas fa-check status-success"></i>
                            <span>Patches Recommended</span>
                        </div>
                        {% endif %}
                    </div>
                </div>
            </section>

            <!-- Quick Actions -->
            <section class="actions-section">
                <h3><i class="fas fa-bolt"></i> Quick Actions</h3>
                <div class="actions-grid">
                    <a href="/download/poc.py" class="action-button">
                        <i class="fas fa-download"></i>
                        Download PoC
                    </a>
                    <a href="/download/advanced_exploit.py" class="action-button">
                        <i class="fas fa-download"></i>
                        Download Exploit
                    </a>
                    <a href="/download/comprehensive_security_report.md" class="action-button">
                        <i class="fas fa-file-alt"></i>
                        Download Report
                    </a>
                    <a href="/exploits" class="action-button primary">
                        <i class="fas fa-rocket"></i>
                        View Exploits
                    </a>
                </div>
            </section>

            <!-- Latest Analysis -->
            {% if llm_data.get('vulnerability_classification') %}
            <section class="latest-analysis">
                <h3><i class="fas fa-microscope"></i> Latest AI Analysis</h3>
                <div class="analysis-content">
                    <div class="analysis-row">
                        <strong>Attack Vector:</strong> {{ llm_data.vulnerability_classification.get('attack_vector', 'Unknown') }}
                    </div>
                    <div class="analysis-row">
                        <strong>Impact:</strong> {{ llm_data.vulnerability_classification.get('impact', 'Unknown') }}
                    </div>
                    {% if llm_data.vulnerability_classification.get('technical_details') %}
                    <div class="analysis-row">
                        <strong>Technical Details:</strong> {{ llm_data.vulnerability_classification.technical_details }}
                    </div>
                    {% endif %}
                </div>
            </section>
            {% endif %}

        </main>

        <!-- Footer -->
        <footer class="dashboard-footer">
            <p>&copy; 2024 Red Team Automation Suite | Generated: {{ metrics.analysis_timestamp }}</p>
        </footer>
    </div>

    <script>
        // Create analysis chart
        const ctx = document.getElementById('analysisChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Crashes Analyzed', 'Unique Frames', 'Protection Checks'],
                datasets: [{
                    data: [{{ metrics.total_crashes }}, {{ metrics.unique_frames }}, 5],
                    backgroundColor: [
                        '#ff6b6b',
                        '#4ecdc4',
                        '#45b7d1'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#ffffff',
                            padding: 20
                        }
                    }
                }
            }
        });
    </script>
</body>
</html>'''
    
    with open(f"{dashboard_dir}/templates/dashboard.html", 'w') as f:
        f.write(template)

def create_dashboard_css(dashboard_dir):
    """Create the sleek CSS styling"""
    
    css = '''/* Red Team Automation Suite - Dashboard Styles */

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
    color: #ffffff;
    min-height: 100vh;
}

.dashboard-container {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
}

/* Header Styles */
.dashboard-header {
    background: rgba(0, 0, 0, 0.3);
    backdrop-filter: blur(10px);
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    padding: 1rem 2rem;
}

.header-content h1 {
    font-size: 2rem;
    font-weight: 700;
    margin-bottom: 0.5rem;
    background: linear-gradient(45deg, #ff6b6b, #4ecdc4);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

.header-content p {
    opacity: 0.8;
    font-size: 1.1rem;
}

.dashboard-nav {
    display: flex;
    gap: 1rem;
    margin-top: 1rem;
}

.nav-item {
    color: rgba(255, 255, 255, 0.7);
    text-decoration: none;
    padding: 0.5rem 1rem;
    border-radius: 8px;
    transition: all 0.3s ease;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.nav-item:hover,
.nav-item.active {
    background: rgba(255, 255, 255, 0.1);
    color: #ffffff;
}

/* Main Content */
.dashboard-main {
    flex: 1;
    padding: 2rem;
    max-width: 1400px;
    margin: 0 auto;
    width: 100%;
}

/* Metrics Grid */
.metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 1.5rem;
    margin-bottom: 2rem;
}

.metric-card {
    background: rgba(255, 255, 255, 0.1);
    backdrop-filter: blur(10px);
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: 16px;
    padding: 2rem;
    display: flex;
    align-items: center;
    gap: 1.5rem;
    transition: transform 0.3s ease, box-shadow 0.3s ease;
}

.metric-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
}

.metric-icon {
    font-size: 3rem;
    opacity: 0.8;
}

.metric-card.vulnerability .metric-icon { color: #ff6b6b; }
.metric-card.crashes .metric-icon { color: #ffa726; }
.metric-card.confidence .metric-icon { color: #4ecdc4; }
.metric-card.protection .metric-icon { color: #45b7d1; }

.metric-content h3 {
    font-size: 2rem;
    font-weight: 700;
    margin-bottom: 0.5rem;
}

.metric-content p {
    opacity: 0.8;
    margin-bottom: 0.5rem;
}

.metric-sub {
    font-size: 0.9rem;
    opacity: 0.6;
}

/* Severity Badges */
.severity-badge {
    padding: 0.3rem 0.8rem;
    border-radius: 20px;
    font-size: 0.8rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.severity-critical { background: #ff4757; }
.severity-high { background: #ff6b6b; }
.severity-medium { background: #ffa726; }
.severity-low { background: #26de81; }
.severity-unknown { background: #778ca3; }

/* Confidence Bar */
.confidence-bar {
    width: 100%;
    height: 8px;
    background: rgba(255, 255, 255, 0.2);
    border-radius: 4px;
    overflow: hidden;
}

.confidence-fill {
    height: 100%;
    background: linear-gradient(90deg, #ff6b6b, #4ecdc4);
    transition: width 1s ease;
}

/* Analysis Grid */
.analysis-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 2rem;
    margin-bottom: 2rem;
}

.analysis-card {
    background: rgba(255, 255, 255, 0.1);
    backdrop-filter: blur(10px);
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: 16px;
    padding: 2rem;
}

.analysis-card h3 {
    margin-bottom: 1.5rem;
    font-size: 1.3rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

/* Status List */
.status-list {
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

.status-item {
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: 0.8rem;
    background: rgba(255, 255, 255, 0.05);
    border-radius: 8px;
}

.status-success { color: #26de81; }
.status-error { color: #ff4757; }

/* Actions Section */
.actions-section {
    margin-bottom: 2rem;
}

.actions-section h3 {
    margin-bottom: 1rem;
    font-size: 1.5rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.actions-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
}

.action-button {
    background: rgba(255, 255, 255, 0.1);
    border: 1px solid rgba(255, 255, 255, 0.2);
    color: #ffffff;
    text-decoration: none;
    padding: 1rem 1.5rem;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    transition: all 0.3s ease;
    font-weight: 500;
}

.action-button:hover {
    background: rgba(255, 255, 255, 0.2);
    transform: translateY(-2px);
}

.action-button.primary {
    background: linear-gradient(45deg, #ff6b6b, #4ecdc4);
    border: none;
}

.action-button.primary:hover {
    transform: translateY(-2px) scale(1.05);
}

/* Latest Analysis */
.latest-analysis {
    background: rgba(255, 255, 255, 0.1);
    backdrop-filter: blur(10px);
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: 16px;
    padding: 2rem;
    margin-bottom: 2rem;
}

.latest-analysis h3 {
    margin-bottom: 1.5rem;
    font-size: 1.3rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.analysis-content {
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

.analysis-row {
    padding: 1rem;
    background: rgba(255, 255, 255, 0.05);
    border-radius: 8px;
    border-left: 4px solid #4ecdc4;
}

/* Footer */
.dashboard-footer {
    background: rgba(0, 0, 0, 0.3);
    text-align: center;
    padding: 1rem;
    opacity: 0.8;
    border-top: 1px solid rgba(255, 255, 255, 0.1);
}

/* Responsive Design */
@media (max-width: 768px) {
    .dashboard-nav {
        flex-wrap: wrap;
    }
    
    .analysis-grid {
        grid-template-columns: 1fr;
    }
    
    .metrics-grid {
        grid-template-columns: 1fr;
    }
    
    .dashboard-main {
        padding: 1rem;
    }
}

/* Animation */
@keyframes fadeInUp {
    from {
        opacity: 0;
        transform: translateY(30px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.metric-card,
.analysis-card,
.latest-analysis {
    animation: fadeInUp 0.6s ease-out;
}'''
    
    with open(f"{dashboard_dir}/static/css/dashboard.css", 'w') as f:
        f.write(css)

def create_report_template(dashboard_dir):
    """Create the report viewing template"""
    
    template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - Red Team Automation Suite</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="{{ url_for('static', filename='css/dashboard.css') }}" rel="stylesheet">
    <style>
        .report-content {
            background: rgba(255, 255, 255, 0.95);
            color: #333;
            padding: 3rem;
            border-radius: 16px;
            margin: 2rem 0;
            line-height: 1.6;
        }
        
        .report-content h1, .report-content h2, .report-content h3 {
            color: #2c3e50;
            margin-top: 2rem;
            margin-bottom: 1rem;
        }
        
        .report-content table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }
        
        .report-content th, .report-content td {
            padding: 0.8rem;
            border: 1px solid #ddd;
            text-align: left;
        }
        
        .report-content th {
            background: #f8f9fa;
            font-weight: 600;
        }
        
        .report-content code {
            background: #f8f9fa;
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
        }
        
        .report-content pre {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
        }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <header class="dashboard-header">
            <div class="header-content">
                <h1><i class="fas fa-file-alt"></i> Security Analysis Report</h1>
                <p>Comprehensive vulnerability assessment results</p>
            </div>
            <nav class="dashboard-nav">
                <a href="/" class="nav-item"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
                <a href="/report" class="nav-item active"><i class="fas fa-file-alt"></i> Report</a>
                <a href="/technical" class="nav-item"><i class="fas fa-code"></i> Technical</a>
                <a href="/exploits" class="nav-item"><i class="fas fa-bug"></i> Exploits</a>
            </nav>
        </header>

        <main class="dashboard-main">
            <div class="report-content">
                {{ report_content | safe }}
            </div>
        </main>

        <footer class="dashboard-footer">
            <p>&copy; 2024 Red Team Automation Suite</p>
        </footer>
    </div>
</body>
</html>'''
    
    with open(f"{dashboard_dir}/templates/report.html", 'w') as f:
        f.write(template)

def create_exploits_template(dashboard_dir):
    """Create the exploits viewing template"""
    
    template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Generated Exploits - Red Team Automation Suite</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="{{ url_for('static', filename='css/dashboard.css') }}" rel="stylesheet">
</head>
<body>
    <div class="dashboard-container">
        <header class="dashboard-header">
            <div class="header-content">
                <h1><i class="fas fa-bug"></i> Generated Exploits</h1>
                <p>AI-generated proof-of-concepts and advanced exploits</p>
            </div>
            <nav class="dashboard-nav">
                <a href="/" class="nav-item"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
                <a href="/report" class="nav-item"><i class="fas fa-file-alt"></i> Report</a>
                <a href="/technical" class="nav-item"><i class="fas fa-code"></i> Technical</a>
                <a href="/exploits" class="nav-item active"><i class="fas fa-bug"></i> Exploits</a>
            </nav>
        </header>

        <main class="dashboard-main">
            
            <section class="exploits-grid">
                
                <!-- Basic PoC -->
                <div class="exploit-card">
                    <div class="exploit-header">
                        <h3><i class="fas fa-vial"></i> Basic Proof of Concept</h3>
                        <div class="status-badge {{ 'success' if poc_exists else 'error' }}">
                            {{ 'Available' if poc_exists else 'Not Generated' }}
                        </div>
                    </div>
                    <div class="exploit-content">
                        <p>AI-generated basic proof-of-concept for vulnerability reproduction.</p>
                        {% if poc_exists %}
                        <div class="exploit-actions">
                            <a href="/download/poc.py" class="action-button">
                                <i class="fas fa-download"></i> Download PoC
                            </a>
                            <button onclick="showCode('poc')" class="action-button">
                                <i class="fas fa-eye"></i> View Code
                            </button>
                        </div>
                        {% endif %}
                    </div>
                </div>

                <!-- Advanced Exploit -->
                <div class="exploit-card">
                    <div class="exploit-header">
                        <h3><i class="fas fa-rocket"></i> Advanced Exploit</h3>
                        <div class="status-badge {{ 'success' if advanced_exists else 'error' }}">
                            {{ 'Available' if advanced_exists else 'Not Generated' }}
                        </div>
                    </div>
                    <div class="exploit-content">
                        <p>Sophisticated exploit with protection bypass techniques.</p>
                        {% if advanced_exists %}
                        <div class="exploit-actions">
                            <a href="/download/advanced_exploit.py" class="action-button">
                                <i class="fas fa-download"></i> Download Exploit
                            </a>
                            <button onclick="showCode('advanced')" class="action-button">
                                <i class="fas fa-eye"></i> View Code
                            </button>
                        </div>
                        {% endif %}
                    </div>
                </div>

                <!-- Mythic C2 Integration -->
                <div class="exploit-card">
                    <div class="exploit-header">
                        <h3><i class="fas fa-network-wired"></i> Mythic C2 Integration</h3>
                        <div class="status-badge {{ 'success' if mythic_exists else 'error' }}">
                            {{ 'Available' if mythic_exists else 'Not Generated' }}
                        </div>
                    </div>
                    <div class="exploit-content">
                        <p>Custom Mythic plugins and C2-ready payloads for operational use.</p>
                        {% if mythic_exists %}
                        <div class="exploit-actions">
                            <a href="https://localhost:7443" target="_blank" class="action-button primary">
                                <i class="fas fa-external-link-alt"></i> Open Mythic
                            </a>
                            <button onclick="showMythicInfo()" class="action-button">
                                <i class="fas fa-info-circle"></i> View Details
                            </button>
                        </div>
                        {% endif %}
                    </div>
                </div>

            </section>

            <!-- Usage Instructions -->
            <section class="instructions-section">
                <h3><i class="fas fa-book"></i> Usage Instructions</h3>
                <div class="instructions-grid">
                    
                    <div class="instruction-card">
                        <h4><i class="fas fa-play"></i> Running Basic PoC</h4>
                        <div class="code-block">
                            <code>python3 poc.py ./target_binary</code>
                        </div>
                        <p>Execute the basic proof-of-concept against your target.</p>
                    </div>

                    <div class="instruction-card">
                        <h4><i class="fas fa-cog"></i> Advanced Exploitation</h4>
                        <div class="code-block">
                            <code>python3 advanced_exploit.py ./target_binary</code>
                        </div>
                        <p>Run the advanced exploit with protection bypass techniques.</p>
                    </div>

                    <div class="instruction-card">
                        <h4><i class="fas fa-shield-alt"></i> Safe Testing</h4>
                        <div class="code-block">
                            <code># Test in isolated environment only</code>
                        </div>
                        <p>Always test exploits in controlled, authorized environments.</p>
                    </div>

                </div>
            </section>

        </main>

        <footer class="dashboard-footer">
            <p>&copy; 2024 Red Team Automation Suite</p>
        </footer>
    </div>

    <style>
        .exploits-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 2rem;
            margin-bottom: 3rem;
        }

        .exploit-card {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 16px;
            padding: 2rem;
            transition: transform 0.3s ease;
        }

        .exploit-card:hover {
            transform: translateY(-5px);
        }

        .exploit-header {
            display: flex;
            justify-content: between;
            align-items: center;
            margin-bottom: 1rem;
        }

        .exploit-header h3 {
            margin: 0;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .status-badge {
            padding: 0.3rem 0.8rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            margin-left: auto;
        }

        .status-badge.success {
            background: #26de81;
            color: #ffffff;
        }

        .status-badge.error {
            background: #ff4757;
            color: #ffffff;
        }

        .exploit-actions {
            display: flex;
            gap: 1rem;
            margin-top: 1rem;
        }

        .instructions-section h3 {
            margin-bottom: 2rem;
            font-size: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .instructions-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
        }

        .instruction-card {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 12px;
            padding: 1.5rem;
        }

        .instruction-card h4 {
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .code-block {
            background: rgba(0, 0, 0, 0.3);
            padding: 1rem;
            border-radius: 8px;
            margin: 1rem 0;
            font-family: 'Courier New', monospace;
        }
    </style>

    <script>
        function showCode(type) {
            alert(`Code viewer for ${type} exploit would open here.`);
        }

        function showMythicInfo() {
            alert('Mythic C2 integration details would be displayed here.');
        }
    </script>
</body>
</html>'''
    
    with open(f"{dashboard_dir}/templates/exploits.html", 'w') as f:
        f.write(template)

def copy_analysis_data(dashboard_dir):
    """Copy analysis data to dashboard data directory"""
    
    data_files = [
        'crash_triage.json',
        'binary_analysis.json',
        'llm_analysis.json',
        'comprehensive_security_report.md'
    ]
    
    for filename in data_files:
        if os.path.exists(filename):
            shutil.copy2(filename, f"{dashboard_dir}/data/")
            print(f"Copied {filename}")

def create_requirements_file(dashboard_dir):
    """Create requirements.txt for the dashboard"""
    
    requirements = '''Flask==2.3.3
markdown==3.4.4
'''
    
    with open(f"{dashboard_dir}/requirements.txt", 'w') as f:
        f.write(requirements)

def create_technical_template(dashboard_dir):
    """Create the technical data viewing template"""
    
    template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Technical Analysis - Red Team Automation Suite</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="{{ url_for('static', filename='css/dashboard.css') }}" rel="stylesheet">
</head>
<body>
    <div class="dashboard-container">
        <header class="dashboard-header">
            <div class="header-content">
                <h1><i class="fas fa-code"></i> Technical Analysis</h1>
                <p>Detailed technical data and JSON analysis results</p>
            </div>
            <nav class="dashboard-nav">
                <a href="/" class="nav-item"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
                <a href="/report" class="nav-item"><i class="fas fa-file-alt"></i> Report</a>
                <a href="/technical" class="nav-item active"><i class="fas fa-code"></i> Technical</a>
                <a href="/exploits" class="nav-item"><i class="fas fa-bug"></i> Exploits</a>
            </nav>
        </header>

        <main class="dashboard-main">
            
            <!-- Crash Triage Data -->
            {% if triage_data %}
            <section class="technical-section">
                <h3><i class="fas fa-bomb"></i> Crash Triage Analysis</h3>
                <div class="json-container">
                    <div class="json-header">
                        <span>Total Crashes: {{ triage_data.total_crashes }}</span>
                        <span>Unique Frames: {{ triage_data.unique_crash_frames }}</span>
                        <button onclick="toggleJson('triage')" class="toggle-btn">
                            <i class="fas fa-chevron-down"></i>
                        </button>
                    </div>
                    <pre id="triage-json" class="json-content collapsed">{{ triage_data | tojson(indent=2) }}</pre>
                </div>
            </section>
            {% endif %}

            <!-- Binary Analysis Data -->
            {% if binary_data %}
            <section class="technical-section">
                <h3><i class="fas fa-shield"></i> Binary Protection Analysis</h3>
                <div class="json-container">
                    <div class="json-header">
                        <span>Protection Level: {{ binary_data.get('exploit_mitigation_summary', {}).get('protection_level', 'Unknown') }}</span>
                        <span>Difficulty: {{ binary_data.get('exploit_mitigation_summary', {}).get('exploit_difficulty', 'Unknown') }}</span>
                        <button onclick="toggleJson('binary')" class="toggle-btn">
                            <i class="fas fa-chevron-down"></i>
                        </button>
                    </div>
                    <pre id="binary-json" class="json-content collapsed">{{ binary_data | tojson(indent=2) }}</pre>
                </div>
            </section>
            {% endif %}

            <!-- LLM Analysis Data -->
            {% if llm_data %}
            <section class="technical-section">
                <h3><i class="fas fa-brain"></i> AI-Powered Analysis</h3>
                <div class="json-container">
                    <div class="json-header">
                        <span>Vulnerability: {{ llm_data.get('vulnerability_classification', {}).get('vulnerability_type', 'Unknown') }}</span>
                        <span>Confidence: {{ (llm_data.get('vulnerability_classification', {}).get('confidence', 0) * 100) | round }}%</span>
                        <button onclick="toggleJson('llm')" class="toggle-btn">
                            <i class="fas fa-chevron-down"></i>
                        </button>
                    </div>
                    <pre id="llm-json" class="json-content collapsed">{{ llm_data | tojson(indent=2) }}</pre>
                </div>
            </section>
            {% endif %}

            <!-- Quick Analysis Summary -->
            <section class="technical-section">
                <h3><i class="fas fa-chart-line"></i> Analysis Summary</h3>
                <div class="summary-grid">
                    
                    {% if triage_data and triage_data.groups %}
                    <div class="summary-card">
                        <h4>Top Crash Locations</h4>
                        <div class="crash-list">
                            {% for frame, data in triage_data.groups.items() %}
                            {% if loop.index <= 3 %}
                            <div class="crash-item">
                                <span class="crash-frame">{{ frame[:50] }}...</span>
                                <span class="crash-count">{{ data.count }} crashes</span>
                            </div>
                            {% endif %}
                            {% endfor %}
                        </div>
                    </div>
                    {% endif %}

                    {% if binary_data %}
                    <div class="summary-card">
                        <h4>Binary Protections</h4>
                        <div class="protection-list">
                            <div class="protection-item">
                                <span>ASLR:</span>
                                <span class="status-{{ 'enabled' if binary_data.get('aslr_system', {}).get('enabled') else 'disabled' }}">
                                    {{ 'Enabled' if binary_data.get('aslr_system', {}).get('enabled') else 'Disabled' }}
                                </span>
                            </div>
                            <div class="protection-item">
                                <span>NX Bit:</span>
                                <span class="status-{{ 'enabled' if binary_data.get('nx_bit', {}).get('enabled') else 'disabled' }}">
                                    {{ 'Enabled' if binary_data.get('nx_bit', {}).get('enabled') else 'Disabled' }}
                                </span>
                            </div>
                            <div class="protection-item">
                                <span>PIE:</span>
                                <span class="status-{{ 'enabled' if binary_data.get('pie', {}).get('enabled') else 'disabled' }}">
                                    {{ 'Enabled' if binary_data.get('pie', {}).get('enabled') else 'Disabled' }}
                                </span>
                            </div>
                            <div class="protection-item">
                                <span>Stack Canaries:</span>
                                <span class="status-{{ 'enabled' if binary_data.get('stack_canaries', {}).get('enabled') else 'disabled' }}">
                                    {{ 'Enabled' if binary_data.get('stack_canaries', {}).get('enabled') else 'Disabled' }}
                                </span>
                            </div>
                        </div>
                    </div>
                    {% endif %}

                    {% if llm_data and llm_data.get('dynamic_exploit_strategy') %}
                    <div class="summary-card">
                        <h4>AI Exploit Strategy</h4>
                        <div class="strategy-content">
                            <p><strong>Approach:</strong> {{ llm_data.dynamic_exploit_strategy.get('exploitation_approach', 'Unknown')[:100] }}...</p>
                            <p><strong>Success Probability:</strong> {{ llm_data.dynamic_exploit_strategy.get('success_probability', 'Unknown') }}</p>
                            <p><strong>Complexity:</strong> {{ llm_data.dynamic_exploit_strategy.get('complexity', 'Unknown') }}</p>
                        </div>
                    </div>
                    {% endif %}

                </div>
            </section>

        </main>

        <footer class="dashboard-footer">
            <p>&copy; 2024 Red Team Automation Suite</p>
        </footer>
    </div>

    <style>
        .technical-section {
            margin-bottom: 3rem;
        }

        .technical-section h3 {
            margin-bottom: 1.5rem;
            font-size: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .json-container {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 16px;
            overflow: hidden;
        }

        .json-header {
            padding: 1rem 1.5rem;
            background: rgba(0, 0, 0, 0.2);
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-weight: 500;
        }

        .toggle-btn {
            background: none;
            border: none;
            color: #ffffff;
            cursor: pointer;
            font-size: 1.2rem;
            transition: transform 0.3s ease;
        }

        .toggle-btn:hover {
            transform: scale(1.1);
        }

        .json-content {
            padding: 1.5rem;
            background: rgba(0, 0, 0, 0.3);
            color: #e0e0e0;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            line-height: 1.4;
            max-height: 400px;
            overflow-y: auto;
            transition: max-height 0.3s ease;
        }

        .json-content.collapsed {
            max-height: 0;
            padding: 0 1.5rem;
            overflow: hidden;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 2rem;
        }

        .summary-card {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 12px;
            padding: 1.5rem;
        }

        .summary-card h4 {
            margin-bottom: 1rem;
            color: #4ecdc4;
        }

        .crash-list, .protection-list {
            display: flex;
            flex-direction: column;
            gap: 0.8rem;
        }

        .crash-item, .protection-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.5rem;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 6px;
        }

        .crash-frame {
            font-family: 'Courier New', monospace;
            font-size: 0.8rem;
            opacity: 0.9;
        }

        .crash-count {
            background: #ff6b6b;
            color: white;
            padding: 0.2rem 0.6rem;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: 600;
        }

        .status-enabled {
            color: #26de81;
            font-weight: 600;
        }

        .status-disabled {
            color: #ff4757;
            font-weight: 600;
        }

        .strategy-content p {
            margin-bottom: 0.5rem;
            line-height: 1.5;
        }
    </style>

    <script>
        function toggleJson(type) {
            const element = document.getElementById(type + '-json');
            const button = element.previousElementSibling.querySelector('.toggle-btn i');
            
            if (element.classList.contains('collapsed')) {
                element.classList.remove('collapsed');
                button.style.transform = 'rotate(180deg)';
            } else {
                element.classList.add('collapsed');
                button.style.transform = 'rotate(0deg)';
            }
        }
    </script>
</body>
</html>'''
    
    with open(f"{dashboard_dir}/templates/technical.html", 'w') as f:
        f.write(template)

def main():
    """Main dashboard generator function"""
    
    print("Generating Professional Security Dashboard...")
    print("=" * 50)
    
    # Create dashboard structure
    dashboard_dir = create_dashboard_structure()
    print(f"Created dashboard directory: {dashboard_dir}")
    
    # Create Flask application
    create_flask_app(dashboard_dir)
    print("Created Flask application")
    
    # Create templates
    create_dashboard_template(dashboard_dir)
    create_report_template(dashboard_dir)
    create_technical_template(dashboard_dir)
    create_exploits_template(dashboard_dir)
    print("Created HTML templates")
    
    # Create CSS
    create_dashboard_css(dashboard_dir)
    print("Created dashboard styling")
    
    # Copy analysis data
    copy_analysis_data(dashboard_dir)
    print("Copied analysis data")
    
    # Create requirements file
    create_requirements_file(dashboard_dir)
    print("Created requirements.txt")
    
    # Create startup script
    startup_script = f'''#!/bin/bash
# Professional Security Dashboard Launcher
echo "Red Team Automation Suite - Professional Dashboard"
echo "=" * 60
echo "Starting professional security dashboard..."
echo ""

cd {dashboard_dir}

# Install requirements if needed
if ! python3 -c "import flask" 2>/dev/null; then
    echo "Installing Flask dependencies..."
    pip3 install -r requirements.txt
fi

# Start the dashboard
echo "Dashboard will be available at: http://localhost:5000"
echo "Features available:"
echo "   • Executive Security Dashboard"
echo "   • AI-Generated Analysis Reports"  
echo "   • Technical Vulnerability Data"
echo "   • Generated Exploits & PoCs"
echo "   • Download Security Artifacts"
echo ""
echo "Press Ctrl+C to stop the dashboard"
echo "=" * 60

python3 app.py
'''
    
    with open("start_dashboard.sh", 'w') as f:
        f.write(startup_script)
    os.chmod("start_dashboard.sh", 0o755)
    
    print("Dashboard generation complete!")
    print("")
    print("PROFESSIONAL SECURITY DASHBOARD READY!")
    print("=" * 50)
    print(f"Dashboard location: {dashboard_dir}/")
    print("Start with: ./start_dashboard.sh")
    print("Access at: http://localhost:5000")
    print("")
    print("Dashboard Features:")
    print("   • Sleek executive overview")
    print("   • AI-powered vulnerability analysis")
    print("   • Interactive metrics and charts")
    print("   • Professional markdown reports")
    print("   • Download all generated artifacts")
    print("   • Mobile-responsive design")

if __name__ == "__main__":
    main()