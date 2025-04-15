import logging
import math
from typing import List, Dict, Any
from ..findings import SecurityFinding

logger = logging.getLogger("patcha")

class SecurityScorer:
    """Calculate security scores based on findings"""
    
    def _get_severity_counts(self, findings: List[SecurityFinding]) -> Dict[str, int]:
        """Count findings by severity"""
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        for finding in findings:
            # Ensure severity is a string and lowercase before checking
            severity = str(getattr(finding, 'severity', 'info')).lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                # Count unknown/unexpected severities as 'info'
                severity_counts["info"] += 1
                logger.warning(f"Finding with unknown severity '{severity}' counted as 'info' for scoring.")
        return severity_counts

    def calculate_score(self, findings: List[SecurityFinding]) -> float:
        """Calculate a security score from 0-10 (10 being most secure)"""
        if not findings:
            return 10.0  # Perfect score if no findings
        
        # Count findings by severity
        severity_counts = self._get_severity_counts(findings)
        
        # --- Increased Weights for each severity level ---
        # These represent the maximum potential penalty for each severity type
        # if many findings of that type exist.
        severity_weights = {
            "critical": 15.0, # Increased significantly
            "high": 10.0,     # Increased significantly
            "medium": 5.0,    # Increased slightly
            "low": 1.5,       # Increased slightly
            "info": 0.2       # Kept low
        }
        
        # --- Calculate penalty for each severity level ---
        total_penalty = 0.0
        # Adjust the diminishing returns factor (lower means steeper penalty increase for more findings)
        diminishing_factor = 0.85 # Was 0.9, now subsequent findings have slightly more impact
        
        for severity, count in severity_counts.items():
            if count > 0 and severity in severity_weights:
                # Calculate the penalty contribution for this severity
                # The penalty approaches severity_weights[severity] as count increases
                penalty_contribution = severity_weights[severity] * (1 - (diminishing_factor ** count))
                total_penalty += penalty_contribution
            elif count > 0:
                 logger.warning(f"Severity '{severity}' found but has no defined weight. Ignoring for penalty calculation.")
        
        # --- Cap the total penalty at 10 points ---
        # Even with higher weights, the maximum score reduction is 10.
        total_penalty = min(total_penalty, 10.0)
        
        # Calculate preliminary score (10 - penalty)
        score = 10.0 - total_penalty
        
        # --- Apply Hard Cap if Critical Findings Exist ---
        # If there's even one critical finding, the score cannot be above this threshold.
        critical_cap = 4.0
        if severity_counts.get("critical", 0) > 0:
            score = min(score, critical_cap)
            logger.debug(f"Applying critical finding score cap. Score adjusted to {score:.1f} (or lower).")
        
        # --- Ensure final score is within bounds [0.0, 10.0] ---
        score = max(0.0, min(score, 10.0))
        
        # Log the final calculated score before returning
        logger.info(f"Calculated Security Score: {score:.1f}/10.0")
        return score
    
    def _determine_category(self, finding: SecurityFinding) -> str:
        """Determine the category of a finding"""
        # Try to get category from metadata
        if finding.metadata and "category" in finding.metadata:
            return finding.metadata["category"].lower()
        
        # Try to determine from the type
        if finding.type:
            type_lower = finding.type.lower()
            if "sql" in type_lower:
                return "sql-injection"
            if "xss" in type_lower or "cross-site" in type_lower:
                return "xss"
            if "command" in type_lower and "inject" in type_lower:
                return "command-injection"
            if "path" in type_lower and "traversal" in type_lower:
                return "path-traversal"
            if "auth" in type_lower:
                return "authentication"
            if "authz" in type_lower or "authoriz" in type_lower:
                return "authorization"
            if "sensitive" in type_lower or "pii" in type_lower:
                return "sensitive-data"
            if "crypto" in type_lower or "cipher" in type_lower or "hash" in type_lower:
                return "crypto"
            if "secret" in type_lower or "password" in type_lower or "key" in type_lower:
                return "secrets"
            if "config" in type_lower or "setting" in type_lower:
                return "configuration"
        
        # Try to determine from the message
        if finding.message:
            msg_lower = finding.message.lower()
            if "sql" in msg_lower and "inject" in msg_lower:
                return "sql-injection"
            if "xss" in msg_lower or "cross-site" in msg_lower:
                return "xss"
            if "command" in msg_lower and "inject" in msg_lower:
                return "command-injection"
            if "path" in msg_lower and "traversal" in msg_lower:
                return "path-traversal"
            if "auth" in msg_lower:
                return "authentication"
            if "authoriz" in msg_lower:
                return "authorization"
            if "sensitive" in msg_lower or "pii" in msg_lower:
                return "sensitive-data"
            if "crypto" in msg_lower or "cipher" in msg_lower or "hash" in msg_lower:
                return "crypto"
            if "secret" in msg_lower or "password" in msg_lower or "key" in msg_lower:
                return "secrets"
            if "config" in msg_lower or "setting" in msg_lower:
                return "configuration"
        
        # Default category
        return "other"
    
    def _determine_grade(self, score: float) -> str:
        """Determine the letter grade based on the score"""
        # Note: This uses a 100-point scale implicitly, adjust if needed for 0-10 scale
        score_100 = score * 10 # Convert 0-10 score to 0-100 for grading
        if score_100 >= 97:
            return "A+"
        elif score_100 >= 93:
            return "A"
        elif score_100 >= 90:
            return "A-"
        elif score_100 >= 87:
            return "B+"
        elif score_100 >= 83:
            return "B"
        elif score_100 >= 80:
            return "B-"
        elif score_100 >= 77:
            return "C+"
        elif score_100 >= 73:
            return "C"
        elif score_100 >= 70:
            return "C-"
        elif score_100 >= 67:
            return "D+"
        elif score_100 >= 63:
            return "D"
        elif score_100 >= 60:
            return "D-"
        else:
            return "F"
    
    def _generate_score_details(self, score: float, severity_counts: Dict[str, int]) -> str:
        """Generate a human-readable description of the score"""
        total_issues = sum(severity_counts.values())
        critical_count = severity_counts.get('critical', 0)
        high_count = severity_counts.get('high', 0)
        
        # Adjust descriptions based on the 0-10 score
        if score >= 9.0:
            return f"Excellent security posture with only {total_issues} minor issues found."
        elif score >= 7.0:
             desc = f"Good security posture with {total_issues} issues found."
             if high_count > 0: desc += f" Includes {high_count} high-severity issues."
             return desc
        elif score >= 5.0:
             desc = f"Moderate security concerns with {total_issues} issues found."
             if critical_count > 0: desc += f" Includes {critical_count} critical issues."
             elif high_count > 0: desc += f" Includes {high_count} high-severity issues."
             return desc
        elif score >= 3.0:
             desc = f"Significant security concerns with {total_issues} issues found."
             if critical_count > 0: desc += f" Includes {critical_count} critical issues."
             if high_count > 0: desc += f" Also includes {high_count} high-severity issues."
             return desc
        else:
             desc = f"Critical security concerns with {total_issues} issues found."
             if critical_count > 0: desc += f" Includes {critical_count} critical issues."
             if high_count > 0: desc += f" Also includes {high_count} high-severity issues."
             return desc 