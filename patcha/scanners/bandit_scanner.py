import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Any
from .base_scanner import BaseScanner
from ..findings import SecurityFinding # Make sure SecurityFinding is imported if needed for add_finding

logger = logging.getLogger("patcha")

class BanditScanner(BaseScanner):
    """Scanner for running Bandit security analysis"""
    
    def scan(self) -> List[Any]:
        """Run Bandit scan for security vulnerabilities"""
        logger.info("Running Bandit scan...")
        # Use a temporary file for results to avoid conflicts if run in parallel
        # Or ensure unique filenames if not using tempfile
        # For simplicity, keeping the original filename for now:
        output_file = self.repo_path / "bandit_results.json"
        command = [
            "bandit", "-r", str(self.repo_path),
            "-f", "json", "-o", str(output_file),
            # Add '-q' for quieter output, '-iii' for high confidence, etc. if desired
        ]

        findings_list = [] # Store findings locally before returning
        try:
            if not self.check_tool_installed("bandit"):
                logger.warning("Bandit not found. Skipping Bandit scan.")
                return []

            result = subprocess.run(
                command, capture_output=True, text=True, check=False, cwd=self.repo_path
            )

            # Handle Bandit exit codes:
            # 0 = Success, no findings
            # 1 = Success, findings found
            # 2 = Error (e.g., bad arguments, file not found)
            if result.returncode == 0:
                logger.info("Bandit scan completed successfully with no findings.")
            elif result.returncode == 1:
                logger.info("Bandit scan completed successfully, findings reported.")
                # Proceed to parse results
            else:
                # Log error for other non-zero exit codes
                error_message = f"Bandit scan failed with exit code {result.returncode}."
                if result.stderr:
                    error_message += f"\nBandit stderr:\n{result.stderr.strip()}"
                else:
                    error_message += " No stderr output from Bandit."
                logger.error(error_message)
                # Optionally raise error or return empty list depending on desired behavior
                # return [] # Stop processing for this scanner on error

            # Log stdout for debug info regardless of exit code
            if result.stdout:
                 logger.debug(f"Bandit stdout:\n{result.stdout.strip()}")

            # Attempt to parse results if the file exists (even if exit code was > 1, maybe partial results)
            if output_file.exists():
                findings_list = self._parse_results(output_file) # Get findings from parser
            elif result.returncode <= 1: # Only warn if file missing on success codes
                logger.warning(f"Bandit output file not found: {output_file}, though exit code was {result.returncode}")

        except FileNotFoundError:
            logger.error("Bandit command not found. Is Bandit installed and in PATH?")
        except Exception as e:
            logger.error(f"An unexpected error occurred during Bandit scan: {e}", exc_info=True)
        finally:
            if output_file.exists():
                try:
                    output_file.unlink()
                except OSError as e:
                    logger.warning(f"Could not remove temporary Bandit file {output_file}: {e}")

        # Return the findings parsed from this scan
        # The main scanner class should aggregate findings from all scanners
        return findings_list
    
    def _parse_results(self, output_file: Path) -> List[SecurityFinding]:
        """Process Bandit findings and return a list of SecurityFinding objects"""
        parsed_findings = []
        try:
            with open(output_file, 'r') as f:
                data = json.load(f)

            # Check for errors reported within the JSON structure itself
            if data.get("errors"):
                 logger.warning(f"Bandit reported errors in JSON output: {data['errors']}")

            results = data.get("results", [])
            for item in results:
                # Map Bandit severity (Low, Medium, High) to your format if needed
                severity_map = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high"}
                severity = severity_map.get(item.get("issue_severity", "MEDIUM"), "medium")

                # Create a SecurityFinding object (ensure class definition matches)
                finding = SecurityFinding(
                    title=item.get("issue_text", "Bandit Finding"),
                    message=f"{item.get('test_name', '')} ({item.get('test_id', '')})",
                    severity=severity,
                    confidence=item.get("issue_confidence", "medium").lower(), # Ensure lowercase
                    file_path=item.get("filename", "").replace(str(self.repo_path) + '/', '', 1), # Make relative
                    line_number=item.get("line_number", 0),
                    code_snippet=item.get("code", ""),
                    scanner="bandit",
                    type=item.get("test_id", "unknown"), # Use Bandit's test ID as type
                    cwe=self._get_cwe(item.get("test_id", "")), # Use helper to get CWE
                    remediation=None, # Bandit doesn't usually provide this directly
                    metadata={"test_id": item.get("test_id"), "test_name": item.get("test_name")},
                    # timestamp will be added by FindingsManager usually
                )
                parsed_findings.append(finding)

        except json.JSONDecodeError:
            logger.error(f"Failed to decode Bandit JSON output from {output_file}")
        except Exception as e:
            logger.error(f"Error parsing Bandit results: {e}", exc_info=True)

        logger.debug(f"Parsed {len(parsed_findings)} findings from Bandit.")
        return parsed_findings # Return the list
    
    def _get_cwe(self, test_id: str) -> str:
        """Map Bandit test ID to CWE (example mapping)"""
        # (Keep your existing CWE map here)
        cwe_map = {
            "B101": "CWE-20", # assert_used
            # ... rest of your map ...
            "B703": "CWE-78",   # Use of django mark_safe
        }
        return cwe_map.get(test_id, "") # Return empty string if no mapping
    
    def _map_severity(self, severity: str) -> str:
        """Map Bandit severity to standardized severity"""
        severity_map = {
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low"
        }
        return severity_map.get(severity.upper(), "medium")
    
    def _map_confidence(self, confidence: str) -> str:
        """Map Bandit confidence to standardized confidence"""
        confidence_map = {
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low"
        }
        return confidence_map.get(confidence.upper(), "medium")
    
    def _map_cwe(self, test_id: str) -> str:
        """Map Bandit test ID to CWE"""
        cwe_map = {
            "B101": "CWE-703",  # Use of assert
            "B102": "CWE-798",  # Exec used
            "B103": "CWE-78",   # Popen with shell=True
            "B104": "CWE-676",  # Binding to all interfaces
            "B105": "CWE-377",  # Use of hardcoded password strings
            "B106": "CWE-259",  # Use of hardcoded password variables
            "B107": "CWE-20",   # Hardcoded password function arguments
            "B108": "CWE-327",  # Insecure cipher mode
            "B109": "CWE-22",   # Password stored in source code
            "B110": "CWE-798",  # Try except pass
            "B111": "CWE-676",  # Execute with run_as_root
            "B112": "CWE-77",   # Try except continue
            "B201": "CWE-78",   # Flask debug mode
            "B301": "CWE-78",   # Pickle and modules that allow remote code execution
            "B302": "CWE-94",   # Deserialization with marshal
            "B303": "CWE-94",   # Use of insecure MD2, MD4, MD5, or SHA1 hash functions
            "B304": "CWE-327",  # Use of insecure cipher mode
            "B305": "CWE-330",  # Use of insecure cipher mode
            "B306": "CWE-327",  # Use of insecure cipher mode
            "B307": "CWE-327",  # Use of insecure cipher mode
            "B308": "CWE-327",  # Use of mark_safe
            "B309": "CWE-327",  # Use of httpsconnection
            "B310": "CWE-327",  # Audit url open for permitted schemes
            "B311": "CWE-330",  # Standard pseudo-random generators are not suitable for security/cryptographic purposes
            "B312": "CWE-676",  # Telnet usage
            "B313": "CWE-676",  # XML parsing vulnerable to XXE
            "B314": "CWE-676",  # Avoid using XML parsing vulnerable to XXE
            "B315": "CWE-676",  # Avoid using XML parsing vulnerable to XXE
            "B316": "CWE-676",  # Avoid using XML parsing vulnerable to XXE
            "B317": "CWE-676",  # Avoid using XML parsing vulnerable to XXE
            "B318": "CWE-676",  # Avoid using XML parsing vulnerable to XXE
            "B319": "CWE-676",  # Avoid using XML parsing vulnerable to XXE
            "B320": "CWE-676",  # Avoid using XML parsing vulnerable to XXE
            "B321": "CWE-676",  # FTP-related functions
            "B322": "CWE-676",  # Input is formatted string
            "B323": "CWE-676",  # Unverified context for SSL
            "B324": "CWE-295",  # Use of insecure MD4, MD5, or SHA1 hash functions
            "B325": "CWE-676",  # Use of os.tempnam or os.tmpnam
            "B401": "CWE-676",  # Import of telnetlib
            "B402": "CWE-676",  # Import of ftplib
            "B403": "CWE-676",  # Import of pickle
            "B404": "CWE-676",  # Import of subprocess without shell=False
            "B405": "CWE-676",  # Import of xml.etree
            "B406": "CWE-676",  # Import of xml.sax
            "B407": "CWE-676",  # Import of xml.expat
            "B408": "CWE-676",  # Import of mark_safe
            "B409": "CWE-676",  # Import of pycrypto
            "B410": "CWE-676",  # Import of lxml.etree
            "B411": "CWE-676",  # Import of xmlrpclib
            "B412": "CWE-676",  # Import of httplib
            "B413": "CWE-676",  # Import of urllib.request
            "B414": "CWE-676",  # Import of cryptography.hazmat
            "B415": "CWE-676",  # Import of cryptography.hazmat
            "B416": "CWE-676",  # Import of cryptography.hazmat
            "B501": "CWE-22",   # Requests call with verify=False disabling SSL certificate checks
            "B502": "CWE-89",   # Use of unsafe yaml load
            "B503": "CWE-78",   # Use of insecure SSL/TLS protocol
            "B504": "CWE-78",   # Use of insecure SSL/TLS protocol
            "B505": "CWE-78",   # Use of weak cryptographic key
            "B506": "CWE-78",   # Use of unsafe yaml load
            "B507": "CWE-78",   # Use of insecure function
            "B601": "CWE-78",   # Possible shell injection
            "B602": "CWE-78",   # Use of popen with shell=True
            "B603": "CWE-78",   # Use of subprocess with shell=True
            "B604": "CWE-78",   # Use of any function with shell=True
            "B605": "CWE-78",   # Use of any function with shell=True
            "B606": "CWE-78",   # Use of any function with shell=True
            "B607": "CWE-78",   # Use of any function with shell=True
            "B608": "CWE-78",   # Use of any function with shell=True
            "B609": "CWE-78",   # Use of any function with shell=True
            "B610": "CWE-78",   # Use of any function with shell=True
            "B611": "CWE-78",   # Use of any function with shell=True
            "B701": "CWE-78",   # Use of jinja2 templates with autoescape=False
            "B702": "CWE-78",   # Use of mako templates with default_filters
            "B703": "CWE-78",   # Use of django mark_safe
        }
        return cwe_map.get(test_id, "") 