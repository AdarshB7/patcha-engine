import logging
from typing import List, Dict, Any
from ..findings import SecurityFinding
import re

logger = logging.getLogger("patcha")

class FindingDeduplicator:
    """Class for deduplicating security findings"""
    
    def deduplicate(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Deduplicate findings based on various criteria"""
        if not findings:
            return []
        
        logger.info(f"Deduplicating {len(findings)} findings")
        
        # First pass: exact duplicates (same file, line, and message)
        unique_findings = self._remove_exact_duplicates(findings)
        logger.info(f"After removing exact duplicates: {len(unique_findings)} findings")
        
        # Second pass: similar findings in the same file
        unique_findings = self._merge_similar_findings(unique_findings)
        logger.info(f"After merging similar findings: {len(unique_findings)} findings")
        
        return unique_findings
    
    def _remove_exact_duplicates(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Remove exact duplicate findings"""
        unique_keys = set()
        unique_findings = []
        
        for finding in findings:
            # Create a unique key for each finding
            key = (
                finding.file_path,
                finding.line_number,
                finding.title,
                finding.scanner
            )
            
            if key not in unique_keys:
                unique_keys.add(key)
                unique_findings.append(finding)
        
        return unique_findings
    
    def _merge_similar_findings(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Merge similar findings in the same file"""
        # Group findings by file
        findings_by_file = {}
        for finding in findings:
            if finding.file_path not in findings_by_file:
                findings_by_file[finding.file_path] = []
            findings_by_file[finding.file_path].append(finding)
        
        # Process each file's findings
        merged_findings = []
        for file_path, file_findings in findings_by_file.items():
            # If only one finding for this file, no need to merge
            if len(file_findings) <= 1:
                merged_findings.extend(file_findings)
                continue
            
            # Group findings by type and proximity
            groups = self._group_by_proximity(file_findings)
            
            # For each group, keep the finding with the highest severity
            for group in groups:
                if len(group) == 1:
                    merged_findings.append(group[0])
                else:
                    merged_findings.append(self._select_best_finding(group))
        
        return merged_findings
    
    def _group_by_proximity(self, findings: List[SecurityFinding]) -> List[List[SecurityFinding]]:
        """Group findings by type and line proximity"""
        # Sort findings by line number
        sorted_findings = sorted(findings, key=lambda f: f.line_number or 0)
        
        groups = []
        current_group = []
        
        for finding in sorted_findings:
            # Start a new group if this is the first finding
            if not current_group:
                current_group.append(finding)
                continue
            
            # Check if this finding is similar to the last one in the current group
            last_finding = current_group[-1]
            
            # Consider findings similar if they have the same type and are within 5 lines
            same_type = finding.type == last_finding.type
            close_lines = (
                finding.line_number is not None and 
                last_finding.line_number is not None and 
                abs(finding.line_number - last_finding.line_number) <= 5
            )
            
            if same_type and close_lines:
                current_group.append(finding)
            else:
                # Start a new group
                groups.append(current_group)
                current_group = [finding]
        
        # Add the last group if it's not empty
        if current_group:
            groups.append(current_group)
        
        return groups
    
    def _select_best_finding(self, findings: List[SecurityFinding]) -> SecurityFinding:
        """Select the best finding from a group of similar findings"""
        # Prioritize by severity
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        
        # Sort by severity (highest first)
        sorted_findings = sorted(
            findings, 
            key=lambda f: severity_order.get(f.severity.lower(), 0), 
            reverse=True
        )
        
        # Return the highest severity finding
        return sorted_findings[0]
    
    def _deduplicate_by_proximity(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Deduplicate findings that are in close proximity to each other"""
        if len(findings) <= 1:
            return findings
        
        # Sort findings by line number
        sorted_findings = sorted(findings, key=lambda f: f.line_number or 0)
        
        # Group findings that are within 5 lines of each other and have the same type
        result = []
        current_group = [sorted_findings[0]]
        
        for i in range(1, len(sorted_findings)):
            current = sorted_findings[i]
            previous = current_group[-1]
            
            # Check if findings are close and of the same type
            if (current.type == previous.type and 
                current.line_number is not None and 
                previous.line_number is not None and
                abs(current.line_number - previous.line_number) <= 5):
                current_group.append(current)
            else:
                # Process the current group
                result.append(self._merge_finding_group(current_group))
                current_group = [current]
        
        # Don't forget the last group
        if current_group:
            result.append(self._merge_finding_group(current_group))
        
        return result
    
    def _merge_finding_group(self, group: List[SecurityFinding]) -> SecurityFinding:
        """Merge a group of similar findings into one"""
        if len(group) == 1:
            return group[0]
        
        # Use the first finding as a base
        base = group[0]
        
        # Collect all line numbers
        line_numbers = sorted(set(f.line_number for f in group if f.line_number is not None))
        
        # Take the highest severity
        severity = "low"
        if any(f.severity == "high" for f in group):
            severity = "high"
        elif any(f.severity == "medium" for f in group):
            severity = "medium"
        
        # Create a consolidated message
        if len(line_numbers) <= 3:
            line_str = ", ".join(str(ln) for ln in line_numbers)
        else:
            line_str = f"{line_numbers[0]}, {line_numbers[1]}, ... and {len(line_numbers)-2} more"
        
        # Merge metadata
        merged_metadata = base.metadata.copy() if base.metadata else {}
        merged_metadata.update({
            "consolidated": True,
            "count": len(group),
            "line_numbers": line_numbers,
            "original_findings": [self._finding_to_key(f) for f in group]
        })
        
        # Create a new finding with merged data
        return SecurityFinding(
            source=base.source,
            tool=base.tool,
            type=base.type,
            severity=severity,
            file_path=base.file_path,
            line_number=line_numbers[0] if line_numbers else None,
            message=f"{base.message} (found at lines {line_str})",
            code_snippet=base.code_snippet,
            remediation=base.remediation,
            metadata=merged_metadata
        )
    
    def _deduplicate_by_similarity(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Deduplicate findings based on semantic similarity"""
        if len(findings) <= 1:
            return findings
        
        # Group findings by similarity of their messages
        groups = []
        processed = set()
        
        for i, finding in enumerate(findings):
            if i in processed:
                continue
                
            # Start a new group
            group = [finding]
            processed.add(i)
            
            # Find similar findings
            for j in range(i+1, len(findings)):
                if j in processed:
                    continue
                    
                other = findings[j]
                if self._are_findings_similar(finding, other):
                    group.append(other)
                    processed.add(j)
            
            groups.append(group)
        
        # Merge each group
        result = []
        for group in groups:
            result.append(self._merge_finding_group(group))
        
        return result
    
    def _are_findings_similar(self, finding1: SecurityFinding, finding2: SecurityFinding) -> bool:
        """Check if two findings are semantically similar"""
        # Different types are not similar
        if finding1.type != finding2.type:
            return False
        
        # Different files are not similar
        if finding1.file_path != finding2.file_path:
            return False
        
        # Compare simplified messages
        msg1 = self._simplify_text(finding1.message)
        msg2 = self._simplify_text(finding2.message)
        
        # Check for high similarity
        return self._text_similarity(msg1, msg2) > 0.8
    
    def _simplify_text(self, text: str) -> str:
        """Simplify text for comparison by removing common variations"""
        if not text:
            return ""
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove common prefixes
        prefixes = ["detected ", "found ", "vulnerability: ", "warning: ", "error: "]
        for prefix in prefixes:
            if text.startswith(prefix):
                text = text[len(prefix):]
        
        # Remove punctuation and extra whitespace
        text = re.sub(r'[^\w\s]', '', text)
        text = re.sub(r'\s+', ' ', text).strip()
        
        # Remove common words that don't add meaning
        stop_words = ["the", "a", "an", "is", "are", "was", "were", "be", "been", "being", 
                     "in", "on", "at", "by", "for", "with", "about", "against", "between",
                     "into", "through", "during", "before", "after", "above", "below", 
                     "to", "from", "up", "down", "of", "off", "over", "under", "again",
                     "further", "then", "once", "here", "there", "when", "where", "why",
                     "how", "all", "any", "both", "each", "few", "more", "most", "other",
                     "some", "such", "no", "nor", "not", "only", "own", "same", "so",
                     "than", "too", "very", "can", "will", "just", "should", "now"]
        
        words = text.split()
        filtered_words = [word for word in words if word not in stop_words]
        
        # Get the most significant words (up to 10)
        significant_words = filtered_words[:10] if len(filtered_words) > 10 else filtered_words
        
        return " ".join(significant_words)
    
    def _text_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity between two texts (0-1)"""
        # Simple Jaccard similarity for word sets
        if not text1 or not text2:
            return 0.0
            
        words1 = set(text1.split())
        words2 = set(text2.split())
        
        intersection = len(words1.intersection(words2))
        union = len(words1.union(words2))
        
        return intersection / union if union > 0 else 0.0
    
    def _finding_to_key(self, finding: SecurityFinding) -> str:
        """Create a unique key for a finding"""
        return f"{finding.file_path}:{finding.line_number}:{finding.type}" 