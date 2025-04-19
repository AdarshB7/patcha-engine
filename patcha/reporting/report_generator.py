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

class ReportGenerator:
    """Generate security reports from findings"""
    
    def __init__(self, repo_path: Path):
        self.repo_path = repo_path
        # Set up Jinja2 environment to load templates from the correct directory
        try:
            self.jinja_env = Environment(
                loader=FileSystemLoader(TEMPLATE_DIR),
                autoescape=select_autoescape(['html', 'xml'])
            )
            # Verify template exists during initialization (optional but good)
            self.jinja_env.get_template("report_template.html") # Check if loadable
            logger.debug(f"Jinja2 environment initialized with template directory: {TEMPLATE_DIR}")
        except Exception as e:
            logger.error(f"Failed to initialize Jinja2 environment or load templates from {TEMPLATE_DIR}: {e}", exc_info=True)
            # Handle error appropriately, maybe raise it or set a flag
            self.jinja_env = None # Prevent further errors
    
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