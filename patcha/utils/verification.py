import logging
import re
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional
from ..findings import SecurityFinding

logger = logging.getLogger("patcha")

class VulnerabilityVerifier:
    """Verify security findings to reduce false positives"""
    
    def __init__(self, repo_path: Path):
        self.repo_path = repo_path
        logger.debug(f"VulnerabilityVerifier initialized for path: {self.repo_path}")
    
    def verify_findings(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Verify findings and filter out false positives"""
        if not findings:
            return []
        
        logger.info(f"Verifying {len(findings)} findings")
        verified_findings = []
        
        for finding in findings:
            try:
                if self._verify_finding(finding):
                    verified_findings.append(finding)
                else:
                    logger.debug(f"Verification removed finding: {finding.rule_id} in {finding.file_path}:{finding.line_number}")
            except Exception as e:
                logger.error(f"Error verifying finding ({finding.rule_id} in {finding.file_path}): {str(e)}", exc_info=True)
                verified_findings.append(finding)
        
        logger.info(f"Verification complete: {len(verified_findings)} of {len(findings)} findings remain.")
        return verified_findings
    
    def _verify_finding(self, finding: SecurityFinding) -> bool:
        """
        Verify a single finding based on its type or rule ID.
        Returns True if the finding is likely valid, False otherwise.
        """
        is_verified = True
        return is_verified
    
    def _verify_secret(self, finding: SecurityFinding) -> bool:
        """Verify a secret detection finding"""
        # Check if it's a known false positive pattern
        false_positive_patterns = [
            "example.com", "localhost", "127.0.0.1",
            "test", "demo", "sample", "example",
            "username", "password", "user", "pass",
            "INSERT_API_KEY_HERE", "YOUR_API_KEY",
            "dummy", "foo", "bar", "baz"
        ]
        
        if finding.code_snippet:
            for pattern in false_positive_patterns:
                if pattern.lower() in finding.code_snippet.lower():
                    logger.debug(f"Secret finding matches false positive pattern: {pattern}")
                    return False
        
        return True
    
    def _verify_sql_injection(self, finding: SecurityFinding) -> bool:
        """Verify a SQL injection finding"""
        # Check if it's in a test file
        if "test" in finding.file_path.lower() or "spec" in finding.file_path.lower():
            # Lower confidence for findings in test files
            finding.confidence = "low"
        
        return True
    
    def _verify_xss(self, finding: SecurityFinding) -> tuple[bool, float, str]:
        """Verify XSS vulnerabilities"""
        if not finding.code_snippet:
            return True, 0.5, "No code to analyze, assuming exploitable"
        
        # Check for proper output encoding
        safe_patterns = [
            r"escapeHtml", r"htmlspecialchars", r"htmlentities", r"sanitize",
            r"DOMPurify", r"textContent", r"innerText", r"encodeURI"
        ]
        
        if any(re.search(pattern, finding.code_snippet) for pattern in safe_patterns):
            return False, 0.7, "Uses proper output encoding or sanitization"
        
        # Check for unsafe patterns
        unsafe_patterns = [
            r"innerHTML", r"outerHTML", r"document\.write", r"eval\(",
            r"dangerouslySetInnerHTML", r"unescaped", r"raw"
        ]
        
        if any(re.search(pattern, finding.code_snippet) for pattern in unsafe_patterns):
            return True, 0.9, "Uses unsafe DOM manipulation methods"
        
        # Check for user input directly output to HTML
        input_to_output = [
            r"echo.*\$_", r"print.*request", r"response\.write.*request",
            r"res\.send\(.*req", r"render\(.*params"
        ]
        
        if any(re.search(pattern, finding.code_snippet, re.IGNORECASE) for pattern in input_to_output):
            return True, 0.8, "User input appears to be output directly to HTML"
        
        return True, 0.6, "Potential XSS, but verification is inconclusive"
    
    def _verify_command_injection(self, finding: SecurityFinding) -> tuple[bool, float, str]:
        """Verify command injection vulnerabilities"""
        if not finding.code_snippet:
            return True, 0.5, "No code to analyze, assuming exploitable"
        
        # Check for command execution functions
        cmd_exec_patterns = [
            r"exec\(", r"shell_exec", r"system\(", r"passthru", r"proc_open",
            r"subprocess", r"popen", r"eval\(", r"os\.system", r"child_process",
            r"spawn", r"execFile", r"ShellExecute"
        ]
        
        has_cmd_exec = any(re.search(pattern, finding.code_snippet) for pattern in cmd_exec_patterns)
        
        if not has_cmd_exec:
            return False, 0.8, "No command execution functions found"
        
        # Check for user input in command
        input_in_cmd = [
            r"exec\(.*request", r"system\(.*\$_", r"subprocess.*input",
            r"os\.system\(.*req", r"child_process.*req\."
        ]
        
        if any(re.search(pattern, finding.code_snippet, re.IGNORECASE) for pattern in input_in_cmd):
            return True, 0.9, "User input appears to be used directly in command execution"
        
        # Check for command sanitization
        safe_patterns = [
            r"escapeshell", r"whitelist", r"allowlist", r"validate", 
            r"filter", r"sanitize"
        ]
        
        if any(re.search(pattern, finding.code_snippet, re.IGNORECASE) for pattern in safe_patterns):
            return False, 0.7, "Command appears to be sanitized or validated"
        
        return True, 0.7, "Potential command injection with unclear sanitization"
    
    def _verify_path_traversal(self, finding: SecurityFinding) -> tuple[bool, float, str]:
        """Verify path traversal vulnerabilities"""
        # Implementation similar to other verification methods
        return True, 0.6, "Path traversal verification not fully implemented"
    
    def _verify_open_redirect(self, finding: SecurityFinding) -> tuple[bool, float, str]:
        """Verify open redirect vulnerabilities"""
        # Implementation similar to other verification methods
        return True, 0.6, "Open redirect verification not fully implemented"
    
    def _verify_insecure_deserialization(self, finding: SecurityFinding) -> tuple[bool, float, str]:
        """Verify insecure deserialization vulnerabilities"""
        # Implementation similar to other verification methods
        return True, 0.7, "Insecure deserialization verification not fully implemented" 