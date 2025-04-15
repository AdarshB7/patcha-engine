import json
import logging
import tempfile
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from .base_scanner import BaseScanner

logger = logging.getLogger("patcha")

class NiktoScanner(BaseScanner):
    """Scanner for running Nikto web vulnerability scans"""
    
    def __init__(self, repo_path: Path, findings_manager, target_url: Optional[str] = None):
        super().__init__(repo_path, findings_manager)
        self.target_url = target_url
    
    def scan(self) -> List[Any]:
        """Run Nikto scan against a target URL"""
        findings = []
        
        # Skip if no target URL is provided
        if not self.target_url:
            logger.info("No target URL provided. Skipping Nikto scan.")
            return findings
        
        try:
            # Check if Nikto is installed
            if not self.check_tool_installed("nikto"):
                logger.warning("Nikto not found. Please install Nikto. Skipping Nikto scan.")
                return findings

            # Create a temporary file for output
            with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as temp_file:
                temp_path = temp_file.name
            
            # Run Nikto with JSON output
            result = self.run_subprocess([
                "nikto", 
                "-h", self.target_url,
                "-Format", "json",
                "-output", temp_path
            ])
            
            if result and result.returncode == 0:
                try:
                    # Read the JSON output file
                    with open(temp_path, 'r') as f:
                        nikto_data = json.load(f)
                    
                    self._process_findings(nikto_data)
                    findings = self.findings_manager.get_findings()
                except json.JSONDecodeError:
                    logger.error("Failed to parse Nikto output")
            else:
                logger.error(f"Nikto scan failed: {result.stderr if result else 'No result'}")
                
            # Clean up temp file
            if os.path.exists(temp_path):
                os.unlink(temp_path)
                
        except Exception as e:
            logger.error(f"Error running Nikto scan: {str(e)}")
        
        return findings
    
    def _process_findings(self, nikto_data: Dict[str, Any]) -> None:
        """Process Nikto findings and add to findings manager"""
        if not nikto_data or "vulnerabilities" not in nikto_data:
            logger.info("No Nikto findings to process")
            return
        
        for vuln in nikto_data["vulnerabilities"]:
            try:
                severity = "medium"  # Default severity
                
                # Try to determine severity based on the message
                if any(kw in vuln.get("message", "").lower() for kw in ["critical", "high", "severe"]):
                    severity = "high"
                elif any(kw in vuln.get("message", "").lower() for kw in ["low", "info", "information"]):
                    severity = "low"
                
                finding = {
                    "title": f"Web Vulnerability: {vuln.get('id', 'Unknown')}",
                    "message": vuln.get("message", "Unknown vulnerability"),
                    "severity": severity,
                    "confidence": "medium",
                    "file_path": None,  # Web vulnerabilities don't have file paths
                    "line_number": None,
                    "code_snippet": None,
                    "scanner": "nikto",
                    "type": "web-vulnerability",
                    "cwe": self._map_to_cwe(vuln.get("id", "")),
                    "metadata": {
                        "raw_result": vuln,
                        "target_url": self.target_url
                    }
                }
                
                self.add_finding(finding)
            except Exception as e:
                logger.error(f"Error processing Nikto finding: {str(e)}")
    
    def _map_to_cwe(self, nikto_id: str) -> str:
        """Map Nikto ID to CWE"""
        # This is a simplified mapping, a complete mapping would be more extensive
        cwe_map = {
            "000001": "CWE-200",  # Information Disclosure
            "000002": "CWE-538",  # File and Directory Information Exposure
            "000003": "CWE-352",  # Cross-Site Request Forgery
            "000004": "CWE-79",   # Cross-site Scripting
            "000005": "CWE-89",   # SQL Injection
            "000006": "CWE-22",   # Path Traversal
            "000007": "CWE-16",   # Configuration
            "000008": "CWE-693",  # Protection Mechanism Failure
            "000009": "CWE-16",   # Configuration
            "000010": "CWE-16",   # Configuration
        }
        return cwe_map.get(nikto_id, "") 