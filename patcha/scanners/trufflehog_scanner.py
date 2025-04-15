import json
import logging
import os # Need os for path check if using full path later
from pathlib import Path
from typing import Dict, List, Any
from .base_scanner import BaseScanner
from ..findings import FindingsManager, SecurityFinding
import tempfile
import subprocess

logger = logging.getLogger("patcha")

class TruffleHogScanner(BaseScanner):
    """Scanner for running TruffleHog secret detection (v3+)"""

    # ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    # +++ ADD BACK the _parse_output method (for v3 JSON lines) ++++++++++++++++
    # ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    def _parse_output(self, output: str):
        """Parse the JSON output from TruffleHog v3."""
        logger.debug("Attempting to parse TruffleHog v3 output.")
        try:
            findings_added = 0
            logger.debug(f"Raw TruffleHog Output:\n---\n{output}\n---")

            for line in output.strip().splitlines():
                if not line:
                    continue
                try:
                    logger.debug(f"Parsing TruffleHog line: {line[:200]}")
                    item = json.loads(line)

                    # Extract fields from v3 JSON structure
                    # Note: v3 structure might differ slightly, adjust keys if needed based on actual output
                    source_meta = item.get("SourceMetadata", {})
                    source_data = source_meta.get("Data", {})
                    git_data = source_data.get("Git") # Might be None if not a git repo scan

                    file_path = "N/A"
                    line_number = 1 # Default line number

                    if git_data: # If Git metadata exists
                         file_path = git_data.get("file", "N/A")
                         line_number = git_data.get("line", 1)
                    elif item.get("SourceType") == "Filesystem": # Check if it's a filesystem scan result
                         # Filesystem scans might put path differently, check raw_finding if needed
                         # This is an example, might need adjustment:
                         file_path = item.get("SourceName", "N/A")
                         # Line number might not be available in simple filesystem scans in all v3 versions
                         # Look within item structure or metadata if needed

                    # Use Redacted field if available, otherwise Raw
                    code_snippet = item.get("Redacted") if item.get("Redacted") else item.get("Raw", "")

                    # Create the SecurityFinding instance
                    finding = SecurityFinding(
                        # Construct a title
                        title=f"Secret Detected ({item.get('DetectorName', 'Unknown Detector')})",
                        scanner="trufflehog",
                        rule_id=item.get("DetectorName", "trufflehog-secret-detected"),
                        file_path=str(file_path),
                        line_number=int(line_number),
                        message=f"Secret detected by {item.get('DetectorName', 'TruffleHog')} in {file_path}",
                        severity="critical", # Secrets are generally critical
                        code_snippet=str(code_snippet),
                        metadata={
                            "raw_finding": item, # Store the raw v3 finding data
                            "decoder": item.get("DecoderName"),
                            "source_type": item.get("SourceType"),
                            "verified": item.get("Verified") # v3 might have verification status
                        }
                    )

                    self.findings_manager.add_finding(finding)
                    findings_added += 1
                    logger.debug(f"Successfully added finding for rule {finding.rule_id} in {finding.file_path}")

                except json.JSONDecodeError as json_err:
                    logger.error(f"TruffleHog v3: FAILED to decode JSON line: {line}. Error: {json_err}")
                except Exception as item_err:
                     logger.error(f"TruffleHog v3: Error processing finding item: {item_err}", exc_info=True)

            if findings_added > 0:
                 logger.info(f"TruffleHog v3: Processed {findings_added} findings.")
            else:
                 if output.strip():
                     logger.warning("TruffleHog v3: Output received, but no findings were successfully parsed.")
                 else:
                     logger.info("TruffleHog v3: No findings reported in the output.")

        except Exception as e:
            logger.error(f"TruffleHog v3: Error parsing overall output: {e}", exc_info=True)
        logger.debug("Finished parsing TruffleHog v3 output.")


    # ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    # +++ ADD BACK the scan method using the v3 'filesystem' command +++++++++++
    # ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    def scan(self):
        """Run TruffleHog scanner (v3+)."""
        logger.info(f"Starting TruffleHog v3+ scan for path: {self.repo_path}")
        
        # Use the full path to the Homebrew-installed TruffleHog
        trufflehog_cmd = "/usr/local/bin/trufflehog"
        
        if not os.path.exists(trufflehog_cmd):
             logger.error(f"{self.name}: TruffleHog executable not found at expected path: {trufflehog_cmd}. Skipping scan.")
             return

        # Create a temporary file for the JSON output
        with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as temp_file:
            output_file = temp_file.name
            
        try:
            # --- Command with additional flags to help with large repos ---
            command = [
                trufflehog_cmd,
                "--json",
                "--no-update",           # Don't check for updates
                "--no-verification",     # Skip verification (faster)
                "--max-depth", "50",     # Limit recursion depth
                "--concurrency", "1",    # Reduce concurrency to avoid timeouts
                "filesystem",
                str(self.repo_path)
            ]
            logger.info(f"Executing TruffleHog command: {' '.join(command)}")

            # --- Use subprocess.Popen with a longer timeout ---
            with open(output_file, 'w') as outfile:
                # Use Popen directly with a longer timeout
                process = subprocess.Popen(
                    command,
                    stdout=outfile,
                    stderr=subprocess.PIPE,
                    text=True
                )
                try:
                    # Wait for the process with a longer timeout (10 minutes)
                    stderr = process.communicate(timeout=600)[1]
                    returncode = process.returncode
                except subprocess.TimeoutExpired:
                    # If it times out, kill the process and note it
                    process.kill()
                    stderr = "Process timed out after 600 seconds and was killed."
                    returncode = -1
                    logger.warning("TruffleHog process timed out after 600 seconds and was killed.")

            logger.info(f"TruffleHog process finished with return code: {returncode}")
            
            # Log stderr for debugging
            if stderr:
                logger.warning(f"TruffleHog stderr:\n---\n{stderr.strip()}\n---")
            
            # Check if the output file exists and has content
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r') as f:
                    output = f.read()
                
                # If we got output, process it
                if output.strip():
                    self._parse_output(output)
                    logger.info(f"Processed TruffleHog output from file: {output_file}")
                else:
                    logger.info("TruffleHog output file exists but is empty.")
            else:
                # No output file or empty file
                if returncode == 0:
                    logger.info("TruffleHog completed successfully with no findings.")
                else:
                    logger.warning(f"TruffleHog exited with code {returncode} and produced no output file.")
            
            # Clean up the temporary file
            if os.path.exists(output_file):
                os.unlink(output_file)
                
            # --- IMPORTANT: Even if we couldn't parse findings from the file ---
            # --- Create findings based on the stderr summary if available ---
            if stderr and "verified_secrets" in stderr:
                try:
                    # Extract the summary line with verified_secrets count
                    summary_lines = [line for line in stderr.splitlines() if "verified_secrets" in line]
                    if summary_lines:
                        summary = summary_lines[-1]  # Take the last one
                        
                        # Try to parse it as JSON
                        try:
                            summary_data = json.loads(summary)
                            verified_count = summary_data.get("verified_secrets", 0)
                            unverified_count = summary_data.get("unverified_secrets", 0)
                            
                            if verified_count > 0 or unverified_count > 0:
                                # Create a single summary finding
                                finding = SecurityFinding(
                                    title=f"TruffleHog Detected Secrets",
                                    scanner="trufflehog",
                                    rule_id="trufflehog-secrets-summary",
                                    file_path="multiple-files",
                                    line_number=0,
                                    message=f"TruffleHog detected {verified_count} verified and {unverified_count} unverified secrets in the repository.",
                                    severity="critical",
                                    code_snippet="[REDACTED]",
                                    metadata={
                                        "verified_count": verified_count,
                                        "unverified_count": unverified_count,
                                        "summary": summary
                                    }
                                )
                                self.findings_manager.add_finding(finding)
                                logger.info(f"Added summary finding for {verified_count} verified and {unverified_count} unverified secrets.")
                        except json.JSONDecodeError:
                            # If it's not valid JSON, try regex extraction
                            import re
                            verified_match = re.search(r'"verified_secrets":(\d+)', summary)
                            unverified_match = re.search(r'"unverified_secrets":(\d+)', summary)
                            
                            verified_count = int(verified_match.group(1)) if verified_match else 0
                            unverified_count = int(unverified_match.group(1)) if unverified_match else 0
                            
                            if verified_count > 0 or unverified_count > 0:
                                # Create a single summary finding
                                finding = SecurityFinding(
                                    title=f"TruffleHog Detected Secrets",
                                    scanner="trufflehog",
                                    rule_id="trufflehog-secrets-summary",
                                    file_path="multiple-files",
                                    line_number=0,
                                    message=f"TruffleHog detected {verified_count} verified and {unverified_count} unverified secrets in the repository.",
                                    severity="critical",
                                    code_snippet="[REDACTED]",
                                    metadata={
                                        "verified_count": verified_count,
                                        "unverified_count": unverified_count,
                                        "summary": summary
                                    }
                                )
                                self.findings_manager.add_finding(finding)
                                logger.info(f"Added summary finding for {verified_count} verified and {unverified_count} unverified secrets.")
                except Exception as e:
                    logger.error(f"Error extracting secret counts from stderr: {e}", exc_info=True)
                
        except FileNotFoundError:
            logger.error(f"TruffleHog command '{command[0]}' not found.", exc_info=True)
        except Exception as e:
            logger.error(f"An unexpected error occurred during the TruffleHog scan: {e}", exc_info=True)
            # Clean up the temporary file in case of exception
            if os.path.exists(output_file):
                os.unlink(output_file)

        logger.info("TruffleHog v3 scan method finished.") 