import logging
import json
import subprocess
import os
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional
from .base_scanner import BaseScanner
from ..findings import FindingsManager, SecurityFinding

logger = logging.getLogger("patcha")

class TrivyScanner(BaseScanner):
    """Scanner for running Trivy vulnerability scanner"""
    
    def scan(self):
        """Run Trivy scanner."""
        logger.info(f"Starting Trivy scan for path: {self.repo_path}")
        
        # Check if Trivy is installed
        trivy_cmd = "trivy"
        try:
            # Check if trivy is available
            subprocess.run([trivy_cmd, "--version"], 
                          stdout=subprocess.PIPE, 
                          stderr=subprocess.PIPE, 
                          check=True)
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.error("Trivy not found. Please install Trivy first.")
            return
            
        # Create a temporary file for the JSON output
        with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as temp_file:
            output_file = temp_file.name
            
        try:
            # Run Trivy with filesystem scanning mode
            command = [
                trivy_cmd,
                "fs",                   # Filesystem scanning mode
                "--format", "json",     # Output in JSON format
                "--security-checks", "vuln,config,secret", # Check for vulnerabilities, misconfigurations, and secrets
                "--quiet",              # Suppress progress bar
                str(self.repo_path)     # Path to scan
            ]
            
            logger.info(f"Executing Trivy command: {' '.join(command)}")
            
            # Execute the command
            process = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False  # Don't raise exception on non-zero exit
            )
            
            # Log the result
            if process.returncode != 0:
                logger.warning(f"Trivy exited with code {process.returncode}")
                if process.stderr:
                    logger.warning(f"Trivy stderr: {process.stderr}")
            
            # Parse the output if we have any
            if process.stdout:
                self._parse_output(process.stdout)
            else:
                logger.info("No output from Trivy scan.")
                
        except Exception as e:
            logger.error(f"Error running Trivy scan: {e}", exc_info=True)
            
    def _parse_output(self, output: str) -> None:
        """Parse Trivy JSON output and create findings."""
        try:
            # Parse the JSON output
            trivy_results = json.loads(output)
            
            # Track how many findings we add
            findings_added = 0
            
            # Process results
            if "Results" in trivy_results:
                for result in trivy_results["Results"]:
                    target = result.get("Target", "Unknown")
                    
                    # Process vulnerabilities
                    if "Vulnerabilities" in result:
                        for vuln in result["Vulnerabilities"]:
                            finding = self._create_vulnerability_finding(vuln, target)
                            if finding:
                                self.findings_manager.add_finding(finding)
                                findings_added += 1
                    
                    # Process misconfigurations
                    if "Misconfigurations" in result:
                        for misconfig in result["Misconfigurations"]:
                            finding = self._create_misconfig_finding(misconfig, target)
                            if finding:
                                self.findings_manager.add_finding(finding)
                                findings_added += 1
                    
                    # Process secrets
                    if "Secrets" in result:
                        for secret in result["Secrets"]:
                            finding = self._create_secret_finding(secret, target)
                            if finding:
                                self.findings_manager.add_finding(finding)
                                findings_added += 1
            
            logger.info(f"Trivy: Added {findings_added} findings.")
            
        except json.JSONDecodeError:
            logger.error("Failed to parse Trivy output as JSON.")
        except Exception as e:
            logger.error(f"Error processing Trivy results: {e}", exc_info=True)
    
    def _create_vulnerability_finding(self, vuln: Dict[str, Any], target: str) -> Optional[SecurityFinding]:
        """Create a SecurityFinding from a Trivy vulnerability."""
        try:
            # Map Trivy severity to our severity levels
            severity_map = {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "UNKNOWN": "info"
            }
            
            severity = severity_map.get(vuln.get("Severity", "UNKNOWN").upper(), "info")
            
            # Create the finding
            return SecurityFinding(
                title=f"Vulnerability: {vuln.get('VulnerabilityID', 'Unknown')}",
                message=vuln.get("Description", "No description provided"),
                rule_id=vuln.get("VulnerabilityID", "trivy-vuln"),
                severity=severity,
                confidence="high",
                file_path=target,
                line_number=0,  # Trivy doesn't always provide line numbers for vulnerabilities
                code_snippet=f"Package: {vuln.get('PkgName', 'Unknown')}, Version: {vuln.get('InstalledVersion', 'Unknown')}",
                scanner="trivy",
                type="vulnerability",
                cwe=vuln.get("CweIDs", [None])[0],  # Take the first CWE if available
                remediation=f"Update to version {vuln.get('FixedVersion', 'latest')} or later",
                metadata={
                    "raw_finding": vuln,
                    "package": vuln.get("PkgName"),
                    "installed_version": vuln.get("InstalledVersion"),
                    "fixed_version": vuln.get("FixedVersion"),
                    "references": vuln.get("References", [])
                }
            )
        except Exception as e:
            logger.error(f"Error creating vulnerability finding: {e}", exc_info=True)
            return None
    
    def _create_misconfig_finding(self, misconfig: Dict[str, Any], target: str) -> Optional[SecurityFinding]:
        """Create a SecurityFinding from a Trivy misconfiguration."""
        try:
            # Map Trivy severity to our severity levels
            severity_map = {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "UNKNOWN": "info"
            }
            
            severity = severity_map.get(misconfig.get("Severity", "UNKNOWN").upper(), "info")
            
            # Create the finding
            return SecurityFinding(
                title=f"Misconfiguration: {misconfig.get('ID', 'Unknown')}",
                message=misconfig.get("Description", "No description provided"),
                rule_id=misconfig.get("ID", "trivy-misconfig"),
                severity=severity,
                confidence="high",
                file_path=target,
                line_number=misconfig.get("Line", 0),
                code_snippet=misconfig.get("Message", "No code snippet available"),
                scanner="trivy",
                type="misconfiguration",
                remediation=misconfig.get("Resolution", "No remediation provided"),
                metadata={
                    "raw_finding": misconfig,
                    "category": misconfig.get("Type"),
                    "references": misconfig.get("References", [])
                }
            )
        except Exception as e:
            logger.error(f"Error creating misconfiguration finding: {e}", exc_info=True)
            return None
    
    def _create_secret_finding(self, secret: Dict[str, Any], target: str) -> Optional[SecurityFinding]:
        """Create a SecurityFinding from a Trivy secret."""
        try:
            # Create the finding
            return SecurityFinding(
                title=f"Secret: {secret.get('RuleID', 'Unknown')}",
                message=f"Secret found: {secret.get('Title', 'Unknown secret')}",
                rule_id=secret.get("RuleID", "trivy-secret"),
                severity="critical",  # Secrets are generally critical
                confidence="high",
                file_path=target,
                line_number=secret.get("Line", 0),
                code_snippet="[REDACTED]",  # Don't include the actual secret
                scanner="trivy",
                type="secret",
                remediation="Remove the secret and use a secure secret management solution",
                metadata={
                    "raw_finding": {k: v for k, v in secret.items() if k != "Match"},  # Don't include the actual secret
                    "category": "secret"
                }
            )
        except Exception as e:
            logger.error(f"Error creating secret finding: {e}", exc_info=True)
            return None 