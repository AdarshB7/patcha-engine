import json
import logging
from collections import defaultdict, Counter
from typing import List, Dict, Any
from .findings import SecurityFinding
from html import escape # Make sure escape is imported at the top
import datetime # Import datetime for timestamp
from pathlib import Path # Import Path

logger = logging.getLogger("patcha")

# SARIF Version and Schema (Moved here)
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# --- Refined CSS ---
def get_html_styles():
    return """
<style>
    body { font-family: sans-serif; margin: 20px; background-color: #f9f9f9; color: #333; }
    h1, h2, h3 { color: #111; border-bottom: 1px solid #ccc; padding-bottom: 5px;}
    h1 { font-size: 2em; }
    h2 { font-size: 1.5em; margin-top: 30px; }
    h3 {
        margin-top: 25px;
        background-color: #e9e9e9;
        padding: 8px;
        border-radius: 4px;
        font-size: 1.1em;
        border-left: 3px solid #666;
    }
    table {
        border-collapse: collapse;
        width: 100%;
        margin-bottom: 20px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        background-color: #fff;
    }
    th, td {
        border: 1px solid #ddd;
        padding: 10px; /* Increased padding */
        text-align: left;
        vertical-align: top; /* Align content to top */
    }
    th {
        background-color: #f2f2f2;
        font-weight: bold;
        color: #444;
    }
    /* Zebra striping */
    tbody tr:nth-child(even) {
        background-color: #f8f8f8;
    }
    tbody tr:hover { /* Add hover effect */
        background-color: #e8f4ff;
    }
    pre {
        background-color: #eee;
        padding: 8px; /* Increased padding */
        border-radius: 4px;
        white-space: pre-wrap;
        word-wrap: break-word;
        max-height: 200px; /* Limit snippet height */
        overflow-y: auto; /* Add scroll if snippet is long */
        border: 1px solid #ccc;
    }
    code { font-family: monospace; font-size: 0.9em; }
    .severity-critical { color: #dc3545; font-weight: bold; } /* Bootstrap danger red */
    .severity-high { color: #fd7e14; font-weight: bold; } /* Bootstrap orange */
    .severity-medium { color: #ffc107; } /* Bootstrap warning yellow */
    .severity-low { color: #0d6efd; } /* Bootstrap primary blue */
    .severity-info { color: #6c757d; } /* Bootstrap secondary grey */
    .summary-table { width: auto; margin-bottom: 30px; } /* Style summary table */
    .timestamp { color: #555; font-size: 0.9em; margin-bottom: 20px; }
</style>
"""

# --- Improved Summary Function ---
def generate_summary_html(findings: List[SecurityFinding]) -> str:
    """Generates an HTML table summarizing findings by severity."""
    severity_counts = Counter(f.severity.lower() for f in findings)
    total_findings = len(findings)

    summary_html = f"""
    <h2>Scan Summary</h2>
    <p>Total Findings: {total_findings}</p>
    <table class="summary-table">
        <thead>
            <tr><th>Severity</th><th>Count</th></tr>
        </thead>
        <tbody>
    """
    # Define order for display
    severity_order = ['critical', 'high', 'medium', 'low', 'info']
    for severity in severity_order:
        count = severity_counts.get(severity, 0)
        if count > 0: # Only show severities with findings
             summary_html += f"""
             <tr>
                 <td class="severity-{escape(severity)}">{escape(severity.capitalize())}</td>
                 <td>{count}</td>
             </tr>
             """
    if total_findings == 0:
        summary_html += "<tr><td colspan='2'>No findings detected.</td></tr>"

    summary_html += """
        </tbody>
    </table>
    """
    return summary_html

# --- Main Report Generation Function (with timestamp and escape checks) ---
def generate_html_report(findings: List[SecurityFinding], output_path: str):
    # Group findings by file_path
    grouped_findings = defaultdict(list)
    for finding in findings:
        file_key = finding.file_path if finding.file_path else "Unknown File"
        grouped_findings[file_key].append(finding)

    sorted_files = sorted(grouped_findings.keys())

    # Get current time for timestamp
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z")

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report</title>
    {get_html_styles()}
</head>
<body>
    <h1>Security Scan Report</h1>
    <p class="timestamp">Generated on: {escape(now)}</p>

    {generate_summary_html(findings)}

    <h2>Findings Details</h2>
    """

    if not findings:
        html_content += "<p>No findings to display.</p>"
    else:
        # Iterate through files
        for file_path in sorted_files:
            # Ensure file_path is escaped in the header
            html_content += f"<h3>{escape(file_path)}</h3>\n"
            html_content += """
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Confidence</th>
                        <th>Rule ID</th>
                        <th>Line</th>
                        <th>Message</th>
                        <th>Code Snippet</th>
                        <!-- Remediation column removed -->
                    </tr>
                </thead>
                <tbody>
            """
            # Iterate through findings for this file
            for finding in grouped_findings[file_path]:
                html_content += generate_finding_row_html(finding) # generate_finding_row_html already escapes content

            html_content += """
                </tbody>
            </table>
            """

    html_content += """
</body>
</html>
    """

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"HTML report generated: {output_path}") # Optional: confirmation message
    except Exception as e:
        print(f"Error writing HTML report to {output_path}: {e}")


# --- Finding Row Generation (already escapes content) ---
def generate_finding_row_html(finding: SecurityFinding) -> str:
    # Ensure all dynamic parts are escaped
    escaped_severity = escape(finding.severity)
    escaped_confidence = escape(finding.confidence)
    escaped_rule_id = escape(finding.rule_id)
    escaped_line = escape(str(finding.line_number)) if finding.line_number else 'N/A'
    escaped_message = escape(finding.message)
    escaped_snippet = escape(finding.code_snippet) if finding.code_snippet else "N/A"

    return f"""
        <tr>
            <td class="severity-{escape(escaped_severity.lower())}">{escaped_severity}</td>
            <td>{escaped_confidence}</td>
            <td>{escaped_rule_id}</td>
            <td>{escaped_line}</td>
            <td>{escaped_message}</td>
            <td><pre><code>{escaped_snippet}</code></pre></td>
            <!-- Remediation cell removed -->
        </tr>
    """ 

def _generate_html_report_content(findings: List[SecurityFinding]) -> str:
    """Generates the HTML content string."""
    # Group findings by file_path
    grouped_findings = defaultdict(list)
    for finding in findings:
        file_key = finding.file_path if finding.file_path else "Unknown File"
        grouped_findings[file_key].append(finding)

    sorted_files = sorted(grouped_findings.keys())
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z")

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Patcha Security Scan Report</title>
    {get_html_styles()}
</head>
<body>
    <h1>Patcha Security Scan Report</h1>
    <p class="timestamp">Generated on: {escape(now)}</p>
    {generate_summary_html(findings)}
    <h2>Findings Details</h2>
    """
    if not findings:
        html_content += "<p>No findings to display.</p>"
    else:
        for file_path in sorted_files:
            html_content += f"<h3>{escape(file_path)}</h3>\n"
            html_content += """
            <table>
                <thead>
                    <tr>
                        <th>Severity</th><th>Confidence</th><th>Rule ID</th><th>Line</th><th>Message</th><th>Code Snippet</th>
                    </tr>
                </thead>
                <tbody>
            """
            for finding in grouped_findings[file_path]:
                html_content += generate_finding_row_html(finding)
            html_content += """
                </tbody>
            </table>
            """
    html_content += "</body></html>"
    return html_content

# --- JSON Generation ---
def _generate_json_report_content(findings: List[SecurityFinding]) -> List[Dict[str, Any]]:
    """Converts SecurityFinding objects to a list of dictionaries for JSON."""
    # Use the to_dict method if available, otherwise manually create dicts
    if findings and hasattr(findings[0], 'to_dict') and callable(findings[0].to_dict):
         return [f.to_dict() for f in findings]
    else:
         # Manual conversion (example, adjust based on SecurityFinding attributes)
         return [
             {
                 "title": f.title,
                 "scanner": f.scanner,
                 "rule_id": f.rule_id,
                 "file_path": f.file_path,
                 "line_number": f.line_number,
                 "message": f.message,
                 "severity": f.severity,
                 "confidence": f.confidence,
                 "code_snippet": f.code_snippet,
                 "type": f.type,
                 "cwe": f.cwe,
                 "remediation": f.remediation,
                 "metadata": f.metadata,
             } for f in findings
         ]


# --- SARIF Generation (Moved Here) ---

def map_severity_to_level(severity: str) -> str:
    """Maps custom severity levels to SARIF levels."""
    severity_lower = severity.lower()
    if severity_lower == "critical":
        return "error"
    elif severity_lower == "high":
        return "error"
    elif severity_lower == "medium":
        return "warning"
    elif severity_lower == "low":
        return "note"
    elif severity_lower == "info":
        return "note"
    else:
        return "warning" # Default level for unknown severities

def format_cwe_uri(cwe_id: str) -> str | None:
    """Formats a CWE ID like 'CWE-798' into a URI."""
    if isinstance(cwe_id, str) and cwe_id.upper().startswith("CWE-"):
        cwe_num = cwe_id.split('-')[-1]
        if cwe_num.isdigit():
            return f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
    return None

def _convert_findings_to_sarif(shield_findings: List[Dict[str, Any]], tool_name: str = "Patcha Security Scanner", tool_version: str = "1.0.0") -> Dict[str, Any]:
    """
    Converts a list of findings (in dictionary format) to a SARIF dictionary.
    """
    sarif_results = []
    sarif_rules = {} # Use dict to store unique rules keyed by rule_id

    for finding in shield_findings:
        rule_id = finding.get("rule_id", "unknown-rule")
        severity = finding.get("severity", "medium") # Default severity
        level = map_severity_to_level(severity)
        message_text = finding.get("message", "No message provided.")
        file_path = finding.get("file_path")
        line_number = finding.get("line_number")
        code_snippet = finding.get("code_snippet")
        confidence = finding.get("confidence")
        scanner = finding.get("scanner", "unknown-scanner")
        cwe = finding.get("cwe")

        # --- Build Location ---
        location = None
        if file_path:
            physical_location = {
                "artifactLocation": {
                    "uri": file_path # Assuming file_path is relative
                }
            }
            region = {}
            if isinstance(line_number, int) and line_number > 0:
                region["startLine"] = line_number
            # SARIF snippet should ideally be the raw text, not the preview/redacted version
            # If code_snippet from finding is already processed, consider getting raw line if possible
            if code_snippet: # Use the snippet provided for now
                region["snippet"] = {"text": code_snippet}

            if region:
                 physical_location["region"] = region

            location = {"physicalLocation": physical_location}

        # --- Build Result ---
        result = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message_text},
        }
        if location:
            result["locations"] = [location]

        # Add optional properties
        properties = {
            "severity": severity, # Keep original severity
            "original_scanner": scanner
        }
        if confidence:
            properties["confidence"] = confidence
        if cwe:
            properties["cwe"] = cwe
        # Add any other relevant metadata if needed
        if "metadata" in finding and isinstance(finding["metadata"], dict):
             properties.update(finding["metadata"]) # Merge metadata

        result["properties"] = properties

        sarif_results.append(result)

        # --- Define Rule if not seen before ---
        if rule_id not in sarif_rules:
            rule_properties = {"tags": ["security", scanner]} # Add scanner as tag
            if severity:
                # SARIF precision relates to confidence/accuracy
                rule_properties["precision"] = confidence.lower() if confidence else "medium"
                # SARIF security-severity maps CVSS score, use custom property for original level
                rule_properties["problem.severity"] = severity.lower()

            help_uri = format_cwe_uri(cwe) if cwe else None

            sarif_rules[rule_id] = {
                "id": rule_id,
                "name": finding.get("title", rule_id).replace(" ", ""), # SARIF names often CamelCase/no space
                "shortDescription": {"text": finding.get("title", f"Issue detected by {scanner}")},
                "fullDescription": {"text": message_text}, # Use first message encountered as description
                "properties": rule_properties
            }
            # Add helpUri if available
            if help_uri:
                sarif_rules[rule_id]["helpUri"] = help_uri
            # Add defaultConfiguration to store severity->level mapping for the rule
            sarif_rules[rule_id]["defaultConfiguration"] = {"level": level}


    # --- Assemble SARIF Structure ---
    sarif_output = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/your-repo/patcha", # TODO: Update with your repo URL
                        "rules": list(sarif_rules.values()) # Convert dict values to list
                    }
                },
                "results": sarif_results,
                # Optionally add invocation details
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.datetime.now(datetime.timezone.utc).isoformat()
                    }
                ]
            }
        ]
    }
    return sarif_output


# --- Main Reporting Function ---
def generate_all_reports(findings: List[SecurityFinding], output_dir: str, base_filename: str = "patcha"):
    """
    Generates JSON, HTML, and SARIF reports from the list of findings.
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True) # Ensure output directory exists

    json_path = output_path / f"{base_filename}.json"
    html_path = output_path / f"{base_filename}.html"
    sarif_path = output_path / f"{base_filename}.sarif"

    # 1. Generate JSON content (list of dicts)
    json_content = _generate_json_report_content(findings)
    try:
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(json_content, f, indent=2)
        logger.info(f"JSON report generated: {json_path}")
    except Exception as e:
        logger.error(f"Error writing JSON report to {json_path}: {e}", exc_info=True)

    # 2. Generate HTML report
    try:
        html_content = _generate_html_report_content(findings)
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        logger.info(f"HTML report generated: {html_path}")
    except Exception as e:
        logger.error(f"Error writing HTML report to {html_path}: {e}", exc_info=True)

    # 3. Generate SARIF report (using the JSON content)
    try:
        sarif_content = _convert_findings_to_sarif(json_content) # Pass the list of dicts
        with open(sarif_path, 'w', encoding='utf-8') as f:
            json.dump(sarif_content, f, indent=2)
        logger.info(f"SARIF report generated: {sarif_path}")
    except Exception as e:
        logger.error(f"Error writing SARIF report to {sarif_path}: {e}", exc_info=True) 