import logging
from typing import Dict, Any
from ..findings import SecurityFinding

logger = logging.getLogger("patcha")

class RemediationGenerator:
    """Generate remediation guidance for security findings"""
    
    def generate_remediation(self, finding: SecurityFinding) -> Dict[str, str]:
        """Generate remediation guidance for a finding"""
        try:
            # Get the appropriate remediation method based on finding type
            if finding.type == "sql-injection":
                return self._remediate_sql_injection(finding)
            elif finding.type == "xss":
                return self._remediate_xss(finding)
            elif finding.type == "secret-detection":
                return self._remediate_secret(finding)
            elif finding.type == "dependency-vulnerability":
                return self._remediate_dependency(finding)
            else:
                # Default remediation based on CWE if available
                if finding.cwe:
                    return self._remediate_by_cwe(finding)
                else:
                    return self._default_remediation(finding)
        except Exception as e:
            logger.error(f"Error generating remediation: {str(e)}")
            return self._default_remediation(finding)
    
    def _default_remediation(self, finding: SecurityFinding) -> Dict[str, str]:
        """Default remediation guidance"""
        return {
            "summary": "Review and fix the security issue",
            "explanation": "This security issue should be reviewed and fixed according to secure coding practices.",
            "code_example": None,
            "references": [
                "https://owasp.org/www-project-top-ten/"
            ]
        }
    
    def _remediate_sql_injection(self, finding: SecurityFinding) -> Dict[str, str]:
        """Remediation for SQL injection"""
        return {
            "summary": "Use parameterized queries",
            "explanation": "Replace dynamic SQL queries with parameterized queries or prepared statements to prevent SQL injection attacks.",
            "code_example": "# Instead of:\ncursor.execute(f\"SELECT * FROM users WHERE username = '{username}'\")\n\n# Use:\ncursor.execute(\"SELECT * FROM users WHERE username = %s\", (username,))",
            "references": [
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                "https://owasp.org/www-community/attacks/SQL_Injection"
            ]
        }
    
    def _remediate_xss(self, finding: SecurityFinding) -> Dict[str, str]:
        """Remediation for XSS"""
        return {
            "summary": "Sanitize user input",
            "explanation": "Always sanitize and validate user input before displaying it in web pages. Use context-appropriate encoding and consider using a template system with automatic escaping.",
            "code_example": "# Instead of:\nresponse.write(f\"<div>{user_input}</div>\")\n\n# Use:\nfrom html import escape\nresponse.write(f\"<div>{escape(user_input)}</div>\")",
            "references": [
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                "https://owasp.org/www-community/attacks/xss/"
            ]
        }
    
    def _remediate_secret(self, finding: SecurityFinding) -> Dict[str, str]:
        """Remediation for hardcoded secrets"""
        return {
            "summary": "Remove hardcoded secrets",
            "explanation": "Remove hardcoded secrets from the code and use environment variables, secure vaults, or configuration files outside of version control.",
            "code_example": "# Instead of:\nAPI_KEY = \"abcd1234\"\n\n# Use:\nimport os\nAPI_KEY = os.environ.get(\"API_KEY\")",
            "references": [
                "https://owasp.org/www-community/vulnerabilities/Hard_coded_password",
                "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
            ]
        }
    
    def _remediate_dependency(self, finding: SecurityFinding) -> Dict[str, str]:
        """Remediation for dependency vulnerabilities"""
        package_name = finding.metadata.get("package_name", "") if finding.metadata else ""
        fixed_version = finding.metadata.get("fixed_version", "") if finding.metadata else ""
        
        explanation = f"Update the vulnerable dependency {package_name} to a secure version"
        if fixed_version:
            explanation += f" (at least {fixed_version})"
        explanation += "."
        
        return {
            "summary": "Update vulnerable dependency",
            "explanation": explanation,
            "code_example": None,
            "references": [
                "https://owasp.org/www-project-dependency-check/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html"
            ]
        }
    
    def _remediate_by_cwe(self, finding: SecurityFinding) -> Dict[str, str]:
        """Remediation based on CWE"""
        cwe = finding.cwe
        
        # Common CWE remediations
        cwe_remediations = {
            "CWE-22": {  # Path Traversal
                "summary": "Validate file paths",
                "explanation": "Validate and sanitize file paths to prevent path traversal attacks. Use absolute paths and restrict access to specific directories.",
                "references": ["https://cwe.mitre.org/data/definitions/22.html"]
            },
            "CWE-78": {  # OS Command Injection
                "summary": "Avoid shell commands",
                "explanation": "Avoid using shell commands with user input. If necessary, use safe APIs and validate all inputs.",
                "references": ["https://cwe.mitre.org/data/definitions/78.html"]
            },
            "CWE-79": {  # XSS
                "summary": "Sanitize output",
                "explanation": "Sanitize all output to prevent cross-site scripting attacks.",
                "references": ["https://cwe.mitre.org/data/definitions/79.html"]
            },
            "CWE-89": {  # SQL Injection
                "summary": "Use parameterized queries",
                "explanation": "Use parameterized queries or prepared statements to prevent SQL injection.",
                "references": ["https://cwe.mitre.org/data/definitions/89.html"]
            },
            "CWE-200": {  # Information Exposure
                "summary": "Limit information exposure",
                "explanation": "Limit the exposure of sensitive information in error messages, logs, and responses.",
                "references": ["https://cwe.mitre.org/data/definitions/200.html"]
            },
            "CWE-287": {  # Authentication Issues
                "summary": "Implement proper authentication",
                "explanation": "Implement proper authentication mechanisms and validate credentials securely.",
                "references": ["https://cwe.mitre.org/data/definitions/287.html"]
            },
            "CWE-327": {  # Broken Cryptography
                "summary": "Use strong cryptography",
                "explanation": "Use strong, modern cryptographic algorithms and implementations.",
                "references": ["https://cwe.mitre.org/data/definitions/327.html"]
            },
            "CWE-352": {  # CSRF
                "summary": "Implement CSRF tokens",
                "explanation": "Implement CSRF tokens for all state-changing operations.",
                "references": ["https://cwe.mitre.org/data/definitions/352.html"]
            },
            "CWE-434": {  # Unrestricted File Upload
                "summary": "Validate file uploads",
                "explanation": "Validate file uploads by checking file types, sizes, and content.",
                "references": ["https://cwe.mitre.org/data/definitions/434.html"]
            },
            "CWE-798": {  # Hardcoded Credentials
                "summary": "Remove hardcoded credentials",
                "explanation": "Remove hardcoded credentials and use secure storage mechanisms.",
                "references": ["https://cwe.mitre.org/data/definitions/798.html"]
            }
        }
        
        # Get remediation for the CWE
        if cwe in cwe_remediations:
            return cwe_remediations[cwe]
        
        # Default remediation
        return {
            "summary": "Fix security vulnerability",
            "explanation": f"Address the security vulnerability identified by {cwe}.",
            "code_example": None,
            "references": [f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html"]
        }