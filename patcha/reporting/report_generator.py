import logging
import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape
from ..findings import SecurityFinding
import jinja2

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
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"security_report_{timestamp}.{report_format}"
        # Place report in the target repository path
        report_path = Path(target_path) / report_filename

        try:
            if report_format == "json":
                return self._generate_json_report(findings, report_path, security_score)
            elif report_format == "html":
                # Check if Jinja env was initialized successfully
                if not self.jinja_env:
                    logger.error("Cannot generate HTML report: Jinja2 environment not available.")
                    return None # Or raise an error
                return self._generate_html_report(findings, report_path, security_score)
            else:
                logger.warning(f"Unsupported report format: {report_format}")
                return None

            logger.info(f"{report_format.upper()} report generated: {report_path}")
            return str(report_path)

        except Exception as e:
            # Catch errors during file writing or template rendering
            logger.error(f"Error generating {report_format} report: {e}", exc_info=True)
            # Specific error for template loading was moved to __init__ or _generate_html_report
            return None # Indicate failure
    
    def _generate_json_report(self, findings: List[SecurityFinding], 
                             report_path: Path,
                             security_score: Optional[float]) -> str:
        """Generate a JSON report"""
        report_data = {
            "scan_timestamp": datetime.now().isoformat(),
            "repository_path": str(self.repo_path),
            "security_score": security_score,
            "findings_count": len(findings),
            "findings": [f.to_dict() for f in findings] # Assuming findings have a to_dict method
        }
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"JSON report generated: {report_path}")
        return str(report_path)
    
    def _generate_html_report(self, findings: List[SecurityFinding],
                             report_path: Path,
                             security_score: Optional[float]) -> Optional[str]:
        """Generate an HTML report"""
        html_content = "" # Initialize empty content
        try:
            # Ensure Jinja environment is available (already checked in generate_report, but double-check)
            if not self.jinja_env:
                 logger.error("Cannot generate HTML report: Jinja2 environment not initialized.")
                 return None

            logger.debug(f"Attempting to load HTML template: report_template.html from {TEMPLATE_DIR}")
            template = self.jinja_env.get_template("report_template.html")
            logger.debug("HTML template loaded successfully.")

            # Prepare context data for the template
            context = {
                "scan_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "repository_path": str(self.repo_path.name), # Just the name might be better for report
                "security_score": f"{security_score:.1f}" if security_score is not None else "N/A",
                "findings": findings, # Pass the list of finding objects
                "severity_counts": self._get_severity_counts(findings), # Helper to count severities
                "findings_count": len(findings) # Add total count for convenience in template
                # Add any other data needed by the template
            }
            logger.debug(f"Rendering HTML template with {len(findings)} findings.")
            html_content = template.render(context)
            logger.debug("HTML template rendered successfully.")

            # --- Add check for empty content ---
            if not html_content or html_content.isspace():
                logger.error("HTML template rendered to empty or whitespace content. Check template logic.")
                # Optionally write the empty file anyway, or return None
                # For debugging, let's write it but log the error.
                # return None # Alternative: return None if content is empty

            # --- Write the content to file ---
            logger.debug(f"Attempting to write HTML report to: {report_path}")
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"HTML report file written successfully: {report_path}")
            return str(report_path) # Return path on success

        except jinja2.exceptions.TemplateNotFound as e:
             logger.error(f"HTML template file 'report_template.html' not found in {TEMPLATE_DIR}: {e}", exc_info=True)
             return None # Return None on failure
        except jinja2.exceptions.TemplateSyntaxError as e:
             logger.error(f"Syntax error in HTML template 'report_template.html' at line {e.lineno}: {e.message}", exc_info=True)
             return None # Return None on failure
        except Exception as e:
            # Log specific HTML generation errors (e.g., template rendering issues, file writing issues)
            logger.error(f"Error generating HTML report content or writing to file {report_path}: {e}", exc_info=True)
            # Don't re-raise, return None to indicate failure
            return None # Return None on failure

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