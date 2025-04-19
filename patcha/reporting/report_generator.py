import logging
import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape
from ..findings import SecurityFinding
import jinja2
# --- Import SARIF converter ---
from ..utils.sarif_converter import convert_shield_to_sarif

logger = logging.getLogger("patcha")

# Determine the directory where this script resides
# This helps locate the template file reliably
SCRIPT_DIR = Path(__file__).parent.resolve()
TEMPLATE_DIR = SCRIPT_DIR / 'templates' # Assuming templates are in a 'templates' subdirectory

# Add this near the top of the file, after imports
DEFAULT_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Patcha Security Scan Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .timestamp {
            color: #7f8c8d;
            font-style: italic;
        }
        .summary {
            background-color: #f8f9fa;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
        }
        .score {
            font-size: 1.2em;
            font-weight: bold;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        .critical { color: #e74c3c; }
        .high { color: #e67e22; }
        .medium { color: #f39c12; }
        .low { color: #3498db; }
        .info { color: #2ecc71; }
        pre {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }
    </style>
</head>
<body>
    <h1>Patcha Security Scan Report</h1>
    <p class="timestamp">Generated on: {{ scan_timestamp }}</p>
    
    <div class="summary">
        <h2>Scan Summary</h2>
        <p><strong>Repository:</strong> {{ repository_path }}</p>
        <p><strong>Security Score:</strong> <span class="score">{{ security_score }}</span></p>
        <p><strong>Total Findings:</strong> {{ findings_count }}</p>
        
        <h3>Findings by Severity</h3>
        <ul>
            <li class="critical">Critical: {{ severity_counts.critical }}</li>
            <li class="high">High: {{ severity_counts.high }}</li>
            <li class="medium">Medium: {{ severity_counts.medium }}</li>
            <li class="low">Low: {{ severity_counts.low }}</li>
            <li class="info">Info: {{ severity_counts.info }}</li>
        </ul>
    </div>
    
    <h2>Findings Details</h2>
    {% if findings_count == 0 %}
        <p>No security findings detected.</p>
    {% else %}
        {% set current_file = "" %}
        {% for finding in findings %}
            {% if finding.file_path != current_file %}
                {% if current_file != "" %}
                    </tbody>
                    </table>
                {% endif %}
                <h3>{{ finding.file_path or "Unknown File" }}</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Rule</th>
                            <th>Line</th>
                            <th>Message</th>
                            <th>Code</th>
                        </tr>
                    </thead>
                    <tbody>
                {% set current_file = finding.file_path %}
            {% endif %}
            <tr>
                <td class="{{ finding.severity }}">{{ finding.severity }}</td>
                <td>{{ finding.rule_id or finding.title }}</td>
                <td>{{ finding.line_number or "N/A" }}</td>
                <td>{{ finding.message }}</td>
                <td>{% if finding.code_snippet %}<pre>{{ finding.code_snippet }}</pre>{% else %}N/A{% endif %}</td>
            </tr>
        {% endfor %}
        </tbody>
        </table>
    {% endif %}
</body>
</html>"""

class ReportGenerator:
    """Generate security reports from findings"""
    
    def __init__(self, repo_path: Path):
        self.repo_path = repo_path
        
        # Ensure template directory exists
        TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)
        
        # Check if template file exists, if not create it
        template_file = TEMPLATE_DIR / "report_template.html"
        if not template_file.exists():
            logger.warning(f"Template file not found at {template_file}, creating default template")
            # Create the template file with the content we provided earlier
            with open(template_file, 'w', encoding='utf-8') as f:
                f.write(DEFAULT_HTML_TEMPLATE)
        
        # Set up Jinja2 environment
        try:
            self.jinja_env = Environment(
                loader=FileSystemLoader(TEMPLATE_DIR),
                autoescape=select_autoescape(['html', 'xml'])
            )
            logger.debug(f"Jinja2 environment initialized with template directory: {TEMPLATE_DIR}")
        except Exception as e:
            logger.error(f"Failed to initialize Jinja2 environment: {e}", exc_info=True)
            self.jinja_env = None
    
    def generate_report(self, findings: List[SecurityFinding], 
                        target_path: Path, 
                        report_format: str,
                        security_score: Optional[float]) -> Optional[str]:
        """Generate a security report in the specified format"""
        # --- Adjust filename generation to use base name ---
        # We'll construct the full path directly in the calling code (bulk.py)
        # This method will now expect the full target_path including filename
        # Let's revert this - bulk.py will call the _generate_* methods directly

        # This method is less useful now if bulk.py calls _generate_* directly
        # Keep it for potential future use or refactor bulk.py to use it
        pass # Or remove/comment out if not used

    def _generate_json_report(self, findings: List[SecurityFinding],
                             report_path: Path, # Expects full path including filename
                             security_score: Optional[float]) -> Optional[str]:
        """Generate a JSON report"""
        logger.info(f"Generating JSON report at: {report_path}")
        try:
            report_data = {
                "scan_timestamp": datetime.now().isoformat(),
                "repository_path": str(self.repo_path),
                "security_score": security_score,
                "findings_count": len(findings),
                "findings": [f.to_dict() for f in findings] # Ensure findings have to_dict
            }
            with open(report_path, 'w', encoding='utf-8') as f: # Add encoding
                json.dump(report_data, f, indent=2)
            logger.info(f"JSON report generated: {report_path}")
            return str(report_path)
        except Exception as e:
            logger.error(f"Error writing JSON report to {report_path}: {e}", exc_info=True)
            return None
    
    def _generate_html_report(self, findings: List[SecurityFinding],
                             report_path: Path, # Expects full path including filename
                             security_score: Optional[float]) -> Optional[str]:
        """Generate an HTML report"""
        logger.info(f"Generating HTML report at: {report_path}")
        
        # Add debug logging
        logger.info(f"ReportGenerator instance has jinja_env: {self.jinja_env is not None}")
        logger.info(f"Template directory exists: {TEMPLATE_DIR.exists()}")
        
        html_content = "" # Initialize empty content
        try:
            # Ensure Jinja environment is available
            if not self.jinja_env:
                # Try to initialize it here as a fallback
                try:
                    logger.info(f"Attempting to initialize Jinja2 environment from {TEMPLATE_DIR}")
                    self.jinja_env = Environment(
                        loader=FileSystemLoader(TEMPLATE_DIR),
                        autoescape=select_autoescape(['html', 'xml'])
                    )
                    logger.info("Jinja2 environment initialized successfully")
                except Exception as je:
                    logger.error(f"Failed to initialize Jinja2 environment: {je}", exc_info=True)
                    return None
                
            # Check if template directory exists
            if not TEMPLATE_DIR.exists():
                logger.error(f"Template directory does not exist: {TEMPLATE_DIR}")
                return None
            
            # List available templates for debugging
            try:
                templates = list(TEMPLATE_DIR.glob('*.html'))
                logger.info(f"Available templates in {TEMPLATE_DIR}: {[t.name for t in templates]}")
            except Exception as e:
                logger.error(f"Error listing templates: {e}")
            
            # Try to get the template
            try:
                template = self.jinja_env.get_template("report_template.html")
                logger.info("Successfully loaded report_template.html")
            except jinja2.exceptions.TemplateNotFound as tnf:
                logger.error(f"Template 'report_template.html' not found: {tnf}")
                return None
            except Exception as e:
                logger.error(f"Error loading template: {e}", exc_info=True)
                return None

            # Prepare context for template rendering
            context = {
                "scan_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "repository_path": str(self.repo_path.name),
                "security_score": f"{security_score:.1f}" if security_score is not None else "N/A",
                "findings": findings,
                "severity_counts": self._get_severity_counts(findings),
                "findings_count": len(findings)
            }
            
            # Render the template
            try:
                html_content = template.render(context)
                logger.info(f"Template rendered successfully, content length: {len(html_content)}")
            except Exception as e:
                logger.error(f"Error rendering template: {e}", exc_info=True)
                return None

            if not html_content or html_content.isspace():
                logger.error("HTML template rendered to empty or whitespace content.")
                return None

            # Write the HTML file
            try:
                with open(report_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                logger.info(f"HTML report file written successfully: {report_path}")
                return str(report_path) # Return path on success
            except Exception as e:
                logger.error(f"Error writing HTML file: {e}", exc_info=True)
                return None

        except Exception as e:
            logger.error(f"Error generating HTML report: {e}", exc_info=True)
            return None

    # --- Add SARIF Generation Method ---
    def _generate_sarif_report(self, findings: List[SecurityFinding],
                              report_path: Path) -> Optional[str]:
        """Generate a SARIF report"""
        logger.info(f"Generating SARIF report at: {report_path}")
        try:
            # Convert findings (which are SecurityFinding objects) to dicts first
            findings_dict_list = [finding.to_dict() for finding in findings] # Use to_dict
            # Generate SARIF content using the converter function
            # Pass repo path as URI for better SARIF context
            repo_uri = self.repo_path.as_uri() if self.repo_path else None
            sarif_content = convert_shield_to_sarif(findings_dict_list, repo_uri=repo_uri)

            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(sarif_content, f, indent=2)
            logger.info(f"SARIF report file written successfully: {report_path}")
            return str(report_path)
        except ImportError:
             logger.error("Failed to generate SARIF report: sarif_converter utility not found or failed to import.")
             return None
        except Exception as e:
            logger.error(f"Error generating SARIF report: {e}", exc_info=True)
            return None

    def _get_severity_counts(self, findings: List[SecurityFinding]) -> dict:
        """Helper method to count findings by severity for the report context"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        default_severity = "info" # Define a default for unexpected values
        for f in findings:
            # Safely get severity, convert to lower, handle None or unexpected values
            severity = getattr(f, 'severity', default_severity)
            if not isinstance(severity, str):
                severity = default_severity
            severity = severity.lower()

            if severity in counts:
                counts[severity] += 1
            else:
                 # Handle unexpected severity values if necessary
                 counts[default_severity] += 1 # Add to default count
                 logger.warning(f"Finding with unexpected severity '{severity}' counted as '{default_severity}' in report counts.")
        return counts 