import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
from .base_scanner import BaseScanner
from ..findings import SecurityFinding, FindingsManager

logger = logging.getLogger("patcha")

class BanditScanner(BaseScanner):
    """Scanner for running Bandit security analysis on Python code"""

    def __init__(self, repo_path: Path, findings_manager: FindingsManager):
        super().__init__(repo_path, findings_manager)
        self.name = "Bandit"

    def scan(self) -> None:
        """Run Bandit scan"""
        if not self.check_tool_installed("bandit"):
            logger.error(f"{self.name}: 'bandit' command not found. Skipping scan.")
            return

        # Command to run Bandit recursively, outputting JSON
        command = [
            "bandit",
            "-r",  # Recursive
            str(self.repo_path),
            "-f", "json", # Output format JSON
            "-q", # Quiet mode to suppress progress/stats, only show JSON/errors
            # Add configuration or specific tests if needed, e.g.,
            # "-c", "bandit.yaml",
            # "-t", "B101,B311" # Run only specific tests
            # Exclude paths if necessary (though Bandit is usually good with Python files)
            # "-x", "./tests/"
        ]
        logger.debug(f"Running command: {' '.join(command)}")

        try:
            result = self.run_subprocess(command, timeout=300) # 5-minute timeout

            if result is None:
                logger.error(f"{self.name}: Scan failed or timed out.")
                return

            # Bandit often puts errors in stderr, even with JSON output
            if result.stderr:
                 # Log stderr at debug level unless it clearly indicates a fatal error
                 logger.debug(f"{self.name} stderr: {result.stderr.strip()}")

            if result.returncode != 0 and not result.stdout.strip():
                 # If Bandit fails and produces no JSON, log error
                 logger.error(f"{self.name}: Scan failed with exit code {result.returncode} and no output.")
                 return
            elif result.returncode != 0:
                 # --- Change log level from WARNING to INFO ---
                 # Log info if exit code is non-zero but there IS output to parse
                 # logger.warning(f"{self.name}: Scan process exited with code {result.returncode}. Attempting to parse output.")
                 logger.info(f"{self.name}: Scan process exited with code {result.returncode}. Attempting to parse output.")


            # Parse the JSON output from stdout
            stdout_content = result.stdout.strip()
            if stdout_content:
                logger.debug(f"{self.name} stdout received ({len(stdout_content)} bytes). Parsing...")
                self._parse_output(stdout_content)
            else:
                 # Handle case where return code was 0 but no output (e.g., no Python files)
                 if result.returncode == 0:
                     logger.info(f"{self.name}: Scan completed with no findings reported (or no Python files found).")
                 # Non-zero exit code with no output already handled above

        except FileNotFoundError:
            logger.error(f"{self.name}: 'bandit' command not found. Is Bandit installed and in PATH?")
        except Exception as e:
            logger.error(f"{self.name}: An unexpected error occurred during Bandit scan: {e}", exc_info=True)


    def _parse_output(self, json_output: str) -> None:
        """Parse Bandit JSON output"""
        try:
            data = json.loads(json_output)
            errors = data.get("errors", [])
            results = data.get("results", [])

            # Log Bandit's internal errors (like file parsing issues) at DEBUG level
            if errors:
                # --- Change log level from WARNING to DEBUG ---
                # logger.warning(f"Bandit reported errors in JSON output: {errors}")
                logger.debug(f"Bandit reported errors in JSON output: {errors}")

            if not results:
                logger.info(f"{self.name}: No findings reported in results.")
                return

            logger.info(f"{self.name}: Processing {len(results)} findings.")
            for item in results:
                try:
                    # Map Bandit severity (LOW, MEDIUM, HIGH) and confidence to your system
                    severity_map = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high"}
                    confidence_map = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high"}

                    severity = severity_map.get(item.get("issue_severity", "MEDIUM"), "medium")
                    confidence = confidence_map.get(item.get("issue_confidence", "MEDIUM"), "medium")

                    # Extract file path relative to repo
                    file_path_str = item.get("filename", "")
                    try:
                        # Ensure the path is absolute before making relative
                        abs_file_path = Path(file_path_str)
                        # Handle cases where Bandit might provide absolute paths already
                        if not abs_file_path.is_absolute():
                             abs_file_path = self.repo_path / file_path_str

                        relative_file_path = abs_file_path.relative_to(self.repo_path)
                        file_path_display = str(relative_file_path)
                    except ValueError:
                        # Handle cases where the path might not be relative (e.g., absolute paths outside repo)
                        file_path_display = file_path_str
                        logger.warning(f"{self.name}: Could not make Bandit path relative: {file_path_str}")


                    finding_obj = SecurityFinding(
                        scanner=self.name,
                        rule_id=item.get("test_id", "unknown"),
                        title=item.get("test_name", "Bandit Finding"), # Use test_name as title
                        severity=severity,
                        confidence=confidence,
                        file_path=file_path_display,
                        line_number=item.get("line_number", 0),
                        message=item.get("issue_text", "No description provided."),
                        code_snippet=item.get("code", ""),
                        cwe=item.get("issue_cwe", {}).get("id", ""), # Extract CWE ID
                        type="sast", # Bandit is SAST
                        metadata={ # Store extra Bandit info
                            "more_info": item.get("more_info", ""),
                            "line_range": item.get("line_range", [])
                        }
                        # Remediation might need separate generation based on test_id/issue_text
                    )
                    self.add_finding(finding_obj)

                except Exception as finding_error:
                    test_id = item.get('test_id', 'N/A')
                    path = item.get('filename', 'N/A')
                    logger.error(f"{self.name}: Error parsing individual Bandit finding (ID: {test_id}, Path: {path}): {finding_error}", exc_info=True)
                    logger.debug(f"Problematic Bandit result dict: {item}")


        except json.JSONDecodeError:
            logger.error(f"{self.name}: Failed to decode Bandit JSON output.")
            logger.debug(f"{self.name} Raw Output (first 500 chars): {json_output[:500]}")
        except Exception as e:
            logger.error(f"{self.name}: Error parsing Bandit results: {e}", exc_info=True)
    
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