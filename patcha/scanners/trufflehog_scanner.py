import json
import logging
import tempfile
import os
from pathlib import Path
from typing import Dict, List, Any
from .base_scanner import BaseScanner

logger = logging.getLogger("patcha")

class TruffleHogScanner(BaseScanner):
    """Scanner for running TruffleHog secret detection"""
    
    def scan(self) -> List[Any]:
        """Run TruffleHog scan for secrets in the repository"""
        findings = []
        try:
            # Check if TruffleHog is installed
            if not self.check_tool_installed("trufflehog"):
                logger.warning("TruffleHog not found. Please install with 'pip install trufflehog'. Skipping TruffleHog scan.")
                return findings

            # Create a temporary file for output
            with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as temp_file:
                temp_path = temp_file.name
            
            # Run TruffleHog with JSON output
            result = self.run_subprocess([
                "trufflehog", 
                "--json",
                "--regex",
                "--entropy=True",
                str(self.repo_path)
            ])
            
            if result and result.returncode in (0, 1):  # TruffleHog returns 1 when it finds secrets
                try:
                    # TruffleHog outputs one JSON object per line
                    for line in result.stdout.splitlines():
                        if line.strip():
                            try:
                                finding_data = json.loads(line)
                                self._process_finding(finding_data)
                            except json.JSONDecodeError:
                                logger.debug(f"Failed to parse TruffleHog line: {line[:100]}")
                    
                    findings = self.findings_manager.get_findings()
                except Exception as e:
                    logger.error(f"Error processing TruffleHog output: {str(e)}")
            else:
                logger.error(f"TruffleHog scan failed: {result.stderr if result else 'No result'}")
                
            # Clean up temp file
            if os.path.exists(temp_path):
                os.unlink(temp_path)
                
        except Exception as e:
            logger.error(f"Error running TruffleHog scan: {str(e)}")
        
        return findings
    
    def _process_finding(self, finding_data: Dict[str, Any]) -> None:
        """Process a TruffleHog finding and add to findings manager"""
        try:
            # Extract relevant information
            reason = finding_data.get("reason", "Unknown Secret")
            path = finding_data.get("path", "")
            line_num = 0  # TruffleHog doesn't provide line numbers directly
            
            # Extract a snippet without exposing the full secret
            snippet = finding_data.get("stringsFound", ["[REDACTED]"])[0]
            if len(snippet) > 20:
                snippet = snippet[:10] + "..." + snippet[-10:]
            
            # Create a finding
            finding = {
                "title": f"Secret Detected: {reason}",
                "message": f"Potential secret found in {path}",
                "severity": "high",  # Secrets are always high severity
                "confidence": "medium",  # Default confidence
                "file_path": path,
                "line_number": line_num,
                "code_snippet": snippet,
                "scanner": "trufflehog",
                "type": "secret-detection",
                "cwe": "CWE-798",  # Use of Hard-coded Credentials
                "metadata": {
                    "commit": finding_data.get("commit", ""),
                    "commitHash": finding_data.get("commitHash", ""),
                    "date": finding_data.get("date", ""),
                    "branch": finding_data.get("branch", ""),
                    "reason": reason
                }
            }
            
            self.add_finding(finding)
        except Exception as e:
            logger.error(f"Error processing TruffleHog finding: {str(e)}")

    def _parse_results(self, json_output: str):
        """Parse TruffleHog JSON output and add findings."""
        try:
            # TruffleHog outputs JSON lines, one per finding
            findings_data = [json.loads(line) for line in json_output.strip().splitlines()]
        except json.JSONDecodeError as e:
            logger.error(f"{self.name}: Failed to decode JSON output: {e}")
            logger.debug(f"{self.name} Raw Output causing error:\n{json_output[:500]}...") # Log snippet
            return
        except Exception as e:
            logger.error(f"{self.name}: Error processing output lines: {e}")
            return

        if not findings_data:
            logger.info(f"{self.name}: No findings reported.")
            return

        logger.info(f"{self.name}: Processing {len(findings_data)} potential secrets.")

        for item in findings_data:
            # --- THIS IS THE CRITICAL PART ---
            # Extract data from the TruffleHog finding dictionary (item)
            # Adjust field names based on the actual TruffleHog JSON structure you receive
            source_metadata = item.get("SourceMetadata", {})
            file_path = source_metadata.get("Data", {}).get("Git", {}).get("file")
            line_number = source_metadata.get("Data", {}).get("Git", {}).get("line")
            commit = source_metadata.get("Data", {}).get("Git", {}).get("commit")
            detector_name = item.get("DetectorName", "Unknown Detector")
            raw_secret = item.get("Raw", "N/A") # The actual secret found

            # Create a SecurityFinding object
            finding = SecurityFinding(
                title=f"Hardcoded Secret Detected ({detector_name})",
                message=f"Potential secret found by {detector_name}. Review the raw secret and context.",
                rule_id=detector_name, # Use detector name as rule ID
                severity="high", # TruffleHog findings are generally high severity
                confidence="high", # Confidence is usually high for pattern matches
                file_path=file_path,
                line_number=line_number,
                code_snippet=raw_secret, # Show the found secret as the snippet
                scanner=self.name,
                metadata={ # Add extra useful info
                    "commit": commit,
                    "raw_secret_preview": raw_secret[:20] + "..." if raw_secret else "N/A" # Avoid logging full secret
                    # Add other relevant fields from 'item' if needed
                }
            )

            # --- Pass the OBJECT, not the dictionary ---
            self.add_finding(finding) # Correct: Pass the SecurityFinding object 