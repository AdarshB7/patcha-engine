import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
from .base_scanner import BaseScanner
from ..findings import SecurityFinding, FindingsManager

logger = logging.getLogger("patcha")

class SemgrepScanner(BaseScanner):
    """Scanner for running Semgrep security analysis"""
    
    def __init__(self, repo_path: Path, findings_manager: FindingsManager):
        super().__init__(repo_path, findings_manager)
        self.name = "Semgrep"

    def scan(self) -> None:
        """Run Semgrep scan for security vulnerabilities"""
        if not self.check_tool_installed("semgrep"):
            logger.error(f"{self.name}: 'semgrep' command not found. Skipping scan.")
            return

        # Adjust config as needed, e.g., "auto" or specific rulesets
        config = "auto"
        command = [
            "semgrep",
            "scan",
            "--config", config,
            "--json",
            "--no-rewrite-rule-ids",
            # --- Add excludes for common non-source files ---
            "--exclude", "*.html",
            "--exclude", "*.css",
            "--exclude", "*.md",
            "--exclude", "*.txt",
            "--exclude", "Dockerfile", # Exclude by filename
            "--exclude", "*.yml",     # Exclude YAML
            "--exclude", "*.yaml",    # Exclude YAML
            # Add more specific paths or patterns if needed
            # e.g., "--exclude", "docs/*"
            # --- Target directory ---
            str(self.repo_path)
        ]
        logger.debug(f"Running command: {' '.join(command)}")

        try:
            # Execute Semgrep, capture stdout and stderr
            result = self.run_subprocess(command, timeout=600)

            if result is None:
                # Error logged within run_subprocess (timeout or other exception)
                logger.error(f"{self.name}: Scan failed or timed out.")
                return

            if result.returncode != 0:
                # Semgrep exited with an error code
                logger.error(f"{self.name}: Scan process exited with code {result.returncode}.")
                stderr_output = result.stderr.strip()
                if stderr_output:
                    max_len = 500
                    log_stderr = stderr_output[:max_len] + ('...' if len(stderr_output) > max_len else '')
                    logger.error(f"{self.name} stderr: {log_stderr}")
                if not result.stdout.strip():
                    logger.error(f"{self.name}: Scan failed with no output.")
                    return
                # Attempt to parse potential partial output even on error

            # Directly parse stdout
            stdout_content = result.stdout.strip()
            if stdout_content:
                logger.debug(f"{self.name} stdout received ({len(stdout_content)} bytes). Parsing...")
                self._parse_results(stdout_content) # Parse directly from stdout
            else:
                # This might happen if return code was 0 but no findings, or non-zero with no output
                 if result.returncode == 0:
                     logger.info(f"{self.name}: Scan completed with no findings reported in output.")
                 else:
                     logger.warning(f"{self.name}: Scan exited with code {result.returncode} and produced no output.")

        except FileNotFoundError:
            logger.error(f"{self.name}: 'semgrep' command not found. Is Semgrep installed and in PATH?")
        except Exception as e:
            logger.error(f"{self.name}: An unexpected error occurred during Semgrep scan: {e}", exc_info=True)

    def _parse_results(self, stdout_content: str) -> None:
        """Process Semgrep scan results"""
        try:
            # Ensure stdout is not empty before trying to parse
            if not stdout_content:
                logger.warning(f"{self.name}: Parsing called with empty stdout content.")
                return

            data = json.loads(stdout_content)
            results = data.get("results", [])
            errors = data.get("errors", []) # Semgrep reports file-specific errors here

            # Log Semgrep's internal errors as warnings
            if errors:
                # Log only a summary or first few errors if the list is long
                error_summary = [f"{e.get('type')}: {e.get('message', '')[:100]}..." for e in errors[:5]]
                logger.warning(f"{self.name} reported {len(errors)} errors during scan (e.g., file parsing issues). Summary: {error_summary}")
                # You could log the full errors list at DEBUG level if needed
                # logger.debug(f"{self.name} full errors: {errors}")

            if not results:
                logger.info(f"{self.name}: No findings reported.")
                return

            logger.info(f"{self.name}: Processing {len(results)} findings.")
            for result in results:
                try:
                    # Default severity if not found or mapping fails
                    default_severity = "medium"
                    severity = default_severity
                    # Check if metadata and severity exist before accessing
                    if "extra" in result and "metadata" in result["extra"] and "severity" in result["extra"]["metadata"]:
                        semgrep_severity = result["extra"]["metadata"]["severity"]
                        # Map Semgrep severity (ERROR, WARNING, INFO) to your system's severity
                        severity_map = {
                            "ERROR": "high",    # Or "critical" depending on your scale
                            "WARNING": "medium",
                            "INFO": "low"       # Or "info"
                        }
                        # Use mapped severity, fall back to default if mapping fails
                        severity = severity_map.get(semgrep_severity, default_severity)
                    else:
                        logger.debug(f"{self.name}: Severity metadata missing for Semgrep rule {result.get('check_id', 'N/A')}. Using default: {default_severity}")

                    # Extract file path relative to repo
                    file_path_str = result.get("path", "")
                    try:
                        # Ensure the path is absolute before making relative
                        abs_file_path = Path(self.repo_path) / file_path_str
                        relative_file_path = abs_file_path.relative_to(self.repo_path)
                        file_path_display = str(relative_file_path)
                    except ValueError:
                        # Handle cases where the path might not be relative (e.g., absolute paths outside repo)
                        file_path_display = file_path_str
                        logger.warning(f"{self.name}: Could not make Semgrep path relative: {file_path_str}")

                    # Get a clean description
                    message = result.get("extra", {}).get("message", "No description provided")
                    # Sometimes the core message is better if extra.message is missing/generic
                    if not message or message == result.get("check_id"):
                         message = result.get("message", message) # Fallback to top-level message

                    # Extract line number
                    line_number = result.get("start", {}).get("line", 0)

                    # Extract code snippet
                    code_snippet = result.get("extra", {}).get("lines", "")

                    # Extract remediation/fix if available
                    remediation = result.get("extra", {}).get("fix", "Review and fix the identified issue")
                    # Sometimes 'fix_regex' provides structured fixes
                    fix_regex = result.get("extra", {}).get("fix_regex")
                    if fix_regex:
                        remediation += f"\nRegex Fix: {json.dumps(fix_regex)}" # Append regex info if present

                    # Extract metadata
                    metadata = result.get("extra", {}).get("metadata", {})
                    cwe_raw = metadata.get("cwe", [])
                    # Ensure CWE is a list of strings or a single string
                    cwe_list = []
                    if isinstance(cwe_raw, list):
                        cwe_list = [str(c) for c in cwe_raw]
                    elif isinstance(cwe_raw, (str, int)):
                         cwe_list = [str(cwe_raw)]
                    # Join multiple CWEs if needed, or take the first one
                    cwe = ", ".join(cwe_list) if cwe_list else ""

                    # Create the SecurityFinding object
                    finding_obj = SecurityFinding(
                        scanner=self.name,
                        # Use rule_id for title if message is generic, otherwise use message
                        title=message.strip() if message.strip() != result.get("check_id") else result.get("check_id", "Semgrep Finding"),
                        rule_id=result.get("check_id", "unknown"),
                        severity=severity,
                        file_path=file_path_display,
                        line_number=line_number,
                        message=message.strip(),
                        code_snippet=code_snippet.strip(),
                        remediation=remediation,
                        cwe=cwe,
                        # Add confidence if available in metadata, else default
                        confidence=metadata.get("confidence", "medium").lower(),
                        # Add type if available in metadata (e.g., 'sast'), else default
                        type=metadata.get("category", "sast"), # Example: map category to type
                        metadata=metadata # Pass the whole metadata dict
                    )

                    # Add the finding object using the inherited method
                    self.add_finding(finding_obj)

                except Exception as finding_error:
                    # Log error for the specific finding but continue with others
                    rule_id = result.get('check_id', 'N/A')
                    path = result.get('path', 'N/A')
                    logger.error(f"{self.name}: Error parsing individual Semgrep finding (Rule: {rule_id}, Path: {path}): {finding_error}", exc_info=True)
                    # Optionally log the problematic 'result' dict for debugging:
                    # logger.debug(f"Problematic Semgrep result dict: {result}")

        except json.JSONDecodeError:
            logger.error(f"{self.name}: Failed to decode Semgrep JSON output")
            logger.debug(f"{self.name} Raw Output (first 500 chars): {stdout_content[:500]}") # Log snippet for debugging
        except Exception as e:
            logger.error(f"{self.name}: Error parsing Semgrep results: {e}", exc_info=True) 

    def _map_severity(self, semgrep_severity: str) -> str:
        """Maps Semgrep severity (INFO, WARNING, ERROR) to Patcha levels."""
        mapping = {
            "ERROR": "high", # Or critical, depending on your scale
            "WARNING": "medium",
            "INFO": "info", # Or low
        }
        return mapping.get(semgrep_severity.upper(), "info").lower() # Default to info, ensure lowercase 