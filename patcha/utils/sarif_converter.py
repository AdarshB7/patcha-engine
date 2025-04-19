import json
import logging
from typing import List, Dict, Any, Optional, Union
from html import escape # Use escape for consistency, though SARIF usually handles text directly
import datetime

# Configure logger if needed, or use the main app's logger
logger = logging.getLogger("patcha") # Or __name__ if run standalone

# SARIF Version and Schema
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

def map_severity_to_level(severity: Optional[str]) -> str:
    """Maps custom severity levels to SARIF levels."""
    if not severity:
        return "note" # Default level if severity is missing
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
        logger.warning(f"Unknown severity level '{severity}', mapping to 'note'.")
        return "note" # Default level for unknown severities

def format_cwe_uri(cwe_id: str) -> Optional[str]:
    """Formats a CWE ID like 'CWE-798' into a URI."""
    if isinstance(cwe_id, str) and cwe_id.upper().startswith("CWE-"):
        cwe_num = cwe_id.split('-')[-1]
        if cwe_num.isdigit():
            return f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
    return None

def convert_shield_to_sarif(
    shield_findings: List[Dict[str, Any]],
    tool_name: str = "Patcha Security Scanner",
    tool_version: str = "1.0.0",
    repo_uri: Optional[str] = None # Add optional repo_uri argument
) -> Dict[str, Any]:
    """
    Converts a list of findings (from shield.json format) to a SARIF dictionary.

    Args:
        shield_findings: List of finding dictionaries.
        tool_name: Name of the scanning tool.
        tool_version: Version of the scanning tool.
        repo_uri: Optional URI of the repository root (e.g., file:///path/to/repo).
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
                    "uri": file_path, # Assuming file_path is relative to repo root
                    # --- Use repo_uri to set uriBaseId ---
                    "uriBaseId": "REPO_ROOT" if repo_uri else None
                }
            }
            region = {}
            if isinstance(line_number, int) and line_number > 0:
                region["startLine"] = line_number
            if code_snippet:
                # Add contextRegion for better display in viewers
                region["contextRegion"] = {
                     "startLine": line_number, # Assuming snippet starts at the finding line
                     "snippet": {"text": code_snippet}
                 }
                # Keep snippet in main region too if needed, but contextRegion is preferred
                # region["snippet"] = {"text": code_snippet}

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

        # --- Add optional properties ---
        properties = {}
        if confidence:
            properties["confidence"] = confidence
        if scanner:
            properties["scanner"] = scanner
        if finding.get("fingerprint"): # Include fingerprint if available
            properties["fingerprint"] = finding.get("fingerprint")
        if properties:
            result["properties"] = properties

        # --- Build Rule Information (if not already present) ---
        if rule_id not in sarif_rules:
            rule_info = {
                "id": rule_id,
                "shortDescription": {"text": finding.get("title", rule_id)}, # Use title if available
                "helpUri": format_cwe_uri(cwe) if cwe else None, # Add CWE link if available
                "properties": {
                    "tags": [scanner] if scanner else [], # Tag with scanner name
                    "precision": confidence.lower() if confidence else "medium",
                    # Add CWE tag if available
                    "security-severity": str(finding.get("cvss_score", "0.0")) # Example CVSS score if available
                }
            }
            # Add CWE tag if present
            if cwe:
                 rule_info["properties"]["tags"].append(f"CWE-{str(cwe).replace('CWE-','')}")

            # Add default severity level to rule
            rule_info["defaultConfiguration"] = {"level": level}

            sarif_rules[rule_id] = rule_info

        sarif_results.append(result)

    # --- Construct the final SARIF object ---
    sarif_output = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/patcha-security/patcha", # TODO: Update with your repo URL
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

    # --- Add originalUriBaseIds if repo_uri was provided ---
    if repo_uri:
        sarif_output["runs"][0]["originalUriBaseIds"] = {
            "REPO_ROOT": {
                "uri": repo_uri,
                "description": {"text": "Repository root"}
            }
        }

    return sarif_output

def convert_file(shield_json_path: str, sarif_output_path: str):
    """Loads shield.json, converts it, and saves as .sarif file."""
    try:
        with open(shield_json_path, 'r', encoding='utf-8') as f:
            shield_data = json.load(f)

        if not isinstance(shield_data, list):
             logger.error(f"Error: Expected a list of findings in {shield_json_path}, found {type(shield_data)}")
             return

        logger.info(f"Read {len(shield_data)} findings from {shield_json_path}")

        sarif_content = convert_shield_to_sarif(shield_data)

        with open(sarif_output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif_content, f, indent=2) # Use indent for readability

        logger.info(f"Successfully converted findings to SARIF format: {sarif_output_path}")

    except FileNotFoundError:
        logger.error(f"Error: Input file not found: {shield_json_path}")
    except json.JSONDecodeError:
        logger.error(f"Error: Could not decode JSON from {shield_json_path}")
    except Exception as e:
        logger.error(f"An unexpected error occurred during SARIF conversion: {e}", exc_info=True)


# Example Usage (if you want to run this file directly)
if __name__ == "__main__":
    # Configure basic logging for direct execution
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Replace with the actual paths
    input_json = "/Users/adarshbulusu/desktop/dv/shield.json"
    output_sarif = "/Users/adarshbulusu/desktop/dv/shield.sarif"

    convert_file(input_json, output_sarif) 