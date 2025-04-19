import logging
import argparse
from pathlib import Path
# ... other necessary imports for scanners, findings manager etc. ...
from patcha.findings import FindingsManager
from patcha.scanners.semgrep_scanner import SemgrepScanner # Example
from patcha.scanners.bandit_scanner import BanditScanner   # Example
from patcha.scanners.trufflehog_scanner import TruffleHogScanner # Example
from patcha.scanners.custom_pattern_scanner import CustomPatternScanner # Example
# Import the new reporting function
from patcha.reporting import generate_all_reports

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("patcha")

def main():
    parser = argparse.ArgumentParser(description="Patcha Security Scanner")
    parser.add_argument("repo_path", help="Path to the repository to scan.")
    parser.add_argument("-o", "--output-dir", default="patcha_reports", help="Directory to save reports.")
    # Add other arguments as needed (e.g., --config, --exclude)
    args = parser.parse_args()

    repo_path = Path(args.repo_path).resolve()
    output_dir = Path(args.output_dir).resolve()

    if not repo_path.is_dir():
        logger.error(f"Repository path not found or not a directory: {repo_path}")
        return

    logger.info(f"Starting scan on: {repo_path}")
    logger.info(f"Reports will be saved to: {output_dir}")

    findings_manager = FindingsManager()

    # --- Initialize and Run Scanners ---
    # Adjust scanner initialization as needed for your project
    scanners = [
        # SemgrepScanner(repo_path, findings_manager), # Uncomment/add your scanners
        # BanditScanner(repo_path, findings_manager),
        TruffleHogScanner(repo_path, findings_manager),
        CustomPatternScanner(repo_path, findings_manager),
        # Add TrivyScanner etc. if implemented
    ]

    for scanner in scanners:
        try:
            # No need for scan() to return findings if using FindingsManager
            scanner.scan()
        except Exception as e:
            logger.error(f"Error running scanner {scanner.name}: {e}", exc_info=True)

    # --- Get All Findings ---
    all_findings = findings_manager.get_findings() # Get findings from the manager
    logger.info(f"Total findings collected: {len(all_findings)}")

    # --- Generate Reports ---
    # Call the single function to generate all reports with base name "patcha"
    generate_all_reports(all_findings, str(output_dir), base_filename="patcha")

    logger.info("Patcha scan finished.")

if __name__ == "__main__":
    main() 