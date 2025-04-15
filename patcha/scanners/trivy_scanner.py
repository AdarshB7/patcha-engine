import json
import logging
import tempfile
import os
from pathlib import Path
from typing import Dict, List, Any
from .base_scanner import BaseScanner

logger = logging.getLogger("patcha")

class TrivyScanner(BaseScanner):
    """Scanner for running Trivy vulnerability scans"""
    
    def scan(self) -> List[Any]:
        """Run Trivy scan for vulnerabilities in dependencies"""
        findings = []
        try:
            # Check if Trivy is installed
            if not self.check_tool_installed("trivy"):
                logger.warning("Trivy not found. Please install Trivy. Skipping Trivy scan.")
                return findings

            # Create a temporary file for output
            with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as temp_file:
                temp_path = temp_file.name
            
            # Run Trivy with JSON output
            result = self.run_subprocess([
                "trivy", 
                "fs",
                "--format", "json",
                "--output", temp_path,
                str(self.repo_path)
            ])
            
            if result and result.returncode == 0:
                try:
                    # Read the JSON output file
                    with open(temp_path, 'r') as f:
                        trivy_data = json.load(f)
                    
                    self._process_findings(trivy_data)
                    findings = self.findings_manager.get_findings()
                except json.JSONDecodeError:
                    logger.error("Failed to parse Trivy output")
            else:
                logger.error(f"Trivy scan failed: {result.stderr if result else 'No result'}")
                
            # Clean up temp file
            if os.path.exists(temp_path):
                os.unlink(temp_path)
                
        except Exception as e:
            logger.error(f"Error running Trivy scan: {str(e)}")
        
        return findings
    
    def _process_findings(self, trivy_data: Dict[str, Any]) -> None:
        """Process Trivy findings and add to findings manager"""
        if not trivy_data or "Results" not in trivy_data:
            logger.info("No Trivy findings to process")
            return
        
        for result in trivy_data["Results"]:
            if "Vulnerabilities" not in result:
                continue
                
            target = result.get("Target", "Unknown")
            
            for vuln in result["Vulnerabilities"]:
                try:
                    severity = self._map_severity(vuln.get("Severity", "MEDIUM"))
                    
                    finding = {
                        "title": f"Dependency Vulnerability: {vuln.get('VulnerabilityID', 'Unknown')}",
                        "message": vuln.get("Description", "Unknown vulnerability"),
                        "severity": severity,
                        "confidence": "high",  # Trivy is usually quite accurate
                        "file_path": target,
                        "line_number": None,
                        "code_snippet": None,
                        "scanner": "trivy",
                        "type": "dependency-vulnerability",
                        "cwe": self._extract_cwe(vuln),
                        "metadata": {
                            "raw_result": vuln,
                            "package_name": vuln.get("PkgName", ""),
                            "installed_version": vuln.get("InstalledVersion", ""),
                            "fixed_version": vuln.get("FixedVersion", ""),
                            "references": vuln.get("References", [])
                        }
                    }
                    
                    self.add_finding(finding)
                except Exception as e:
                    logger.error(f"Error processing Trivy finding: {str(e)}")
    
    def _map_severity(self, severity: str) -> str:
        """Map Trivy severity to standardized severity"""
        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "UNKNOWN": "info"
        }
        return severity_map.get(severity.upper(), "medium")
    
    def _extract_cwe(self, vuln: Dict[str, Any]) -> str:
        """Extract CWE from Trivy vulnerability data"""
        # Try to find CWE in references
        for ref in vuln.get("References", []):
            if "cwe.mitre.org/data/definitions/" in ref:
                cwe_id = ref.split("definitions/")[-1].split(".")[0]
                return f"CWE-{cwe_id}"
        
        # Try to find CWE in CVSS vector
        cvss_vector = vuln.get("CVSS", {}).get("V3Vector", "")
        if "CWE-" in cvss_vector:
            cwe_match = re.search(r'CWE-(\d+)', cvss_vector)
            if cwe_match:
                return f"CWE-{cwe_match.group(1)}"
        
        return "" 