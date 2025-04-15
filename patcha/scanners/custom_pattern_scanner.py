import re
import logging
from pathlib import Path
from typing import Dict, List, Any, Pattern
from .base_scanner import BaseScanner
from ..findings import SecurityFinding

logger = logging.getLogger("patcha")

class CustomPatternScanner(BaseScanner):
    """Scanner for detecting custom security patterns"""
    
    def __init__(self, repo_path: Path, findings_manager):
        super().__init__(repo_path, findings_manager)
        self.patterns = self._get_patterns()
    
    def scan(self) -> List[Any]:
        """Scan repository for custom security patterns"""
        findings = []
        try:
            # Get all files to scan
            files_to_scan = self._get_files_to_scan()
            logger.info(f"Scanning {len(files_to_scan)} files for custom patterns")
            
            # Scan each file
            for file_path in files_to_scan:
                self._scan_file(file_path)
            
            findings = self.findings_manager.get_findings()
        except Exception as e:
            logger.error(f"Error in custom pattern scan: {str(e)}")
        
        return findings
    
    def _get_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Get custom security patterns to scan for"""
        return {
            # Hardcoded credentials
            "password": {
                "pattern": re.compile(r'(?i)(password|passwd|pwd)\s*=\s*["\']([^"\']+)["\']'),
                "title": "Hardcoded Password",
                "message": "Hardcoded password found in source code",
                "severity": "high",
                "confidence": "medium",
                "type": "hardcoded-secret",
                "cwe": "CWE-798"
            },
            # Insecure cryptographic functions
            "md5": {
                "pattern": re.compile(r'(?i)(md5|hashlib\.md5)'),
                "title": "Insecure Cryptographic Function",
                "message": "MD5 is a weak hashing algorithm and should not be used",
                "severity": "medium",
                "confidence": "high",
                "type": "weak-crypto",
                "cwe": "CWE-327"
            },
            # SQL Injection
            "sql_injection": {
                "pattern": re.compile(r'(?i)(execute|executemany|cursor\.execute)\s*\(\s*["\'].*\%s.*["\']'),
                "title": "Potential SQL Injection",
                "message": "String formatting used in SQL query could lead to SQL injection",
                "severity": "high",
                "confidence": "medium",
                "type": "sql-injection",
                "cwe": "CWE-89"
            },
            # Command Injection
            "command_injection": {
                "pattern": re.compile(r'(?i)(os\.system|subprocess\.call|subprocess\.Popen|eval|exec)\s*\(\s*["\']'),
                "title": "Potential Command Injection",
                "message": "Dynamic command execution could lead to command injection",
                "severity": "high",
                "confidence": "medium",
                "type": "command-injection",
                "cwe": "CWE-78"
            },
            # Insecure deserialization
            "insecure_deserialization": {
                "pattern": re.compile(r'(?i)(pickle\.loads|yaml\.load|marshal\.loads)'),
                "title": "Insecure Deserialization",
                "message": "Insecure deserialization can lead to remote code execution",
                "severity": "high",
                "confidence": "high",
                "type": "insecure-deserialization",
                "cwe": "CWE-502"
            }
        }
    
    def _get_files_to_scan(self) -> List[Path]:
        """Get list of files to scan"""
        extensions = ['.py', '.js', '.ts', '.java', '.php', '.rb', '.go', '.c', '.cpp', '.h', '.hpp']
        files = []
        
        for ext in extensions:
            files.extend(list(self.repo_path.glob(f"**/*{ext}")))
        
        # Filter out files in common directories to ignore
        ignore_dirs = ['node_modules', 'venv', '.git', '.vscode', '__pycache__', 'build', 'dist']
        return [f for f in files if not any(ignore_dir in str(f) for ignore_dir in ignore_dirs)]
    
    def _scan_file(self, file_path: Path) -> None:
        """Scan a single file for all patterns"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            lines = content.splitlines()
            
            for pattern_name, pattern_info in self.patterns.items():
                pattern = pattern_info["pattern"]
                
                for i, line in enumerate(lines):
                    match = pattern.search(line)
                    if match:
                        self._add_pattern_finding(pattern_name, pattern_info, file_path, i+1, line)
        except Exception as e:
            logger.debug(f"Error scanning file {file_path}: {str(e)}")
    
    def _add_pattern_finding(self, pattern_name: str, pattern_info: Dict[str, Any],
                             file_path: Path, line_number: int, line: str) -> None:
        """Create a SecurityFinding object and add it to the findings manager"""
        try:
            # Create a SecurityFinding object directly
            finding_obj = SecurityFinding(
                title=pattern_info.get("title", "Custom Pattern Match"), # Use .get with default
                message=pattern_info.get("message", "Pattern matched in file"), # Use .get with default
                rule_id=pattern_name, # Use the pattern name as the rule_id
                severity=pattern_info.get("severity", "medium"), # Use .get with default
                confidence=pattern_info.get("confidence", "medium"), # Use .get with default
                file_path=str(file_path.relative_to(self.repo_path)),
                line_number=line_number,
                code_snippet=line.strip(),
                scanner="custom-pattern", # Set scanner name
                type=pattern_info.get("type", "custom"), # Use .get with default
                cwe=pattern_info.get("cwe"), # Use .get, allows None
                remediation=pattern_info.get("remediation"), # Add remediation if defined in pattern_info
                metadata={ # Keep relevant metadata
                    "pattern_name": pattern_name,
                    # Add other metadata from pattern_info if needed
                    # "pattern_regex": pattern_info["pattern"].pattern # Example: store regex string
                }
            )

            # Pass the SecurityFinding object to the base class add_finding method
            self.add_finding(finding_obj)

        except Exception as e:
            # Log error specific to creating/adding this finding
            logger.error(
                f"Error creating/adding custom pattern finding for "
                f"pattern '{pattern_name}' in file {file_path}: {e}",
                exc_info=True # Include traceback for debugging
            ) 