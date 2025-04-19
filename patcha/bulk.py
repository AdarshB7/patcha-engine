import os
import sys
import json
import subprocess
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
import ast
import re
from datetime import datetime
import tempfile
from .findings import FindingsManager, SecurityFinding
from .logger import PatchaLogger
import concurrent.futures
from functools import partial

# Import new modules
from .scanners.semgrep_scanner import SemgrepScanner
from .scanners.bandit_scanner import BanditScanner
from .scanners.trufflehog_scanner import TruffleHogScanner
from .scanners.custom_pattern_scanner import CustomPatternScanner
from .scanners.nikto_scanner import NiktoScanner
from .scanners.trivy_scanner import TrivyScanner
from .utils.file_utils import FileUtils
from .utils.deduplication import FindingDeduplicator
from .utils.verification import VulnerabilityVerifier
from .utils.scoring import SecurityScorer
from .utils.remediation import RemediationGenerator
from .reporting.report_generator import ReportGenerator
from .utils.sarif_converter import convert_shield_to_sarif

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("patcha")

class SecurityScanner:
    def __init__(self, repo_path: str, output_file: Optional[str] = None, verbose: bool = False):
        self.repo_path = Path(repo_path).resolve()
        if not self.repo_path.is_dir():
            raise ValueError(f"Repository path does not exist or is not a directory: {self.repo_path}")

        self.logger = PatchaLogger(verbose=verbose)

        # --- Setup output path for shield.json ---
        # Use the provided output file name, default to 'patcha.json'
        # Place it directly in the repository root.
        output_filename = output_file if output_file else "patcha.json"
        self.output_path = self.repo_path / output_filename
        # Ensure the parent directory (repo root) exists, which it should
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.logger.info(f"Primary output summary will be saved to: {self.output_path}")
        # Store base filename for other reports
        self.base_filename = self.output_path.stem

        # --- Initialize components ---
        self.findings_manager = FindingsManager()
        self.file_utils = FileUtils(self.repo_path)
        self.deduplicator = FindingDeduplicator()
        self.verifier = VulnerabilityVerifier(self.repo_path)
        self.scorer = SecurityScorer()
        self.remediation_generator = RemediationGenerator()
        try:
            # Pass repo_path to ReportGenerator
            self.report_generator = ReportGenerator(self.repo_path)
        except ImportError as e:
            self.logger.warning(f"Could not import ReportGenerator (missing dependencies like Jinja2?): {e}. HTML/SARIF reporting might be limited.")
            self.report_generator = None
        except Exception as e: # Catch other potential init errors
             self.logger.error(f"Failed to initialize ReportGenerator: {e}", exc_info=True)
             self.report_generator = None


        self.findings: List[SecurityFinding] = []
        self.security_score: Optional[float] = None

    def _run_scanner(self, scanner_class: type, name: str) -> None:
        """Helper to instantiate and run a scanner."""
        try:
            scanner = scanner_class(self.repo_path, self.findings_manager)
            scanner.scan()
        except NotImplementedError:
             self.logger.error(f"{name} scanner's scan method is not implemented.")
        except Exception as e:
            # Log the error using the logger's tool_error method for consistency
            self.logger.tool_error(name, str(e))
            self.logger.debug(f"Traceback for error in {name}:", exc_info=True) # Log full traceback at debug level

    def scan(self, target_url: Optional[str] = None) -> None:
        """Main scanning function"""
        self.logger.start_scan(str(self.repo_path))

        # Define scan phases (name, function_to_call)
        scan_phases = [
            ("Semgrep", partial(self._run_scanner, SemgrepScanner, "Semgrep")),
            ("Bandit", partial(self._run_scanner, BanditScanner, "Bandit")),
            ("TruffleHog", partial(self._run_scanner, TruffleHogScanner, "TruffleHog")),
            # ("Custom Patterns", partial(self._run_scanner, CustomPatternScanner, "Custom Patterns")), # Example
            # Add Nikto and Trivy if applicable and configured
            # ("Nikto", partial(self._run_scanner, NiktoScanner, "Nikto", target_url=target_url)), # Needs target_url
            # ("Trivy FS", partial(self._run_scanner, TrivyScanner, "Trivy FS")),
        ]
        # Filter out phases that shouldn't run (e.g., Nikto without URL)
        # scan_phases = [phase for phase in scan_phases if self._should_run_phase(phase[0], target_url)]

        # --- Simplified Scan Execution Loop ---
        try:
            for phase_name, phase_func in scan_phases:
                self.logger.tool_start(phase_name)
                try:
                    phase_func()
                    self.logger.tool_complete(phase_name)
                except Exception as e:
                    # Error is logged within _run_scanner or here if phase_func raises directly
                    self.logger.tool_error(phase_name, f"Phase execution failed: {str(e)}")
                    self.logger.debug(f"Traceback for error in {phase_name}:", exc_info=True)
                    # Continue to the next phase even if one fails

            # --- Deduplicate findings ---
            self.logger.tool_start("Deduplication")
            initial_count = len(self.findings_manager.findings)
            self.findings = self.deduplicator.deduplicate(self.findings_manager.findings)
            final_count = len(self.findings)
            self.logger.info(f"Deduplication reduced findings from {initial_count} to {final_count}.")
            self.logger.tool_complete("Deduplication") # Log completion

            # --- Verify findings ---
            self.logger.tool_start("Verification")
            verified_count_before = len(self.findings)
            self.findings = self.verifier.verify_findings(self.findings)
            verified_count_after = len(self.findings)
            if verified_count_after < verified_count_before:
                 self.logger.info(f"Verification removed {verified_count_before - verified_count_after} findings (from {verified_count_before} to {verified_count_after}).")
            elif verified_count_before == 0:
                 self.logger.info("Verification skipped (no findings to verify).")
            else:
                 self.logger.info(f"Verification confirmed all {verified_count_after} findings.")
            if verified_count_before > 0 and verified_count_after == 0:
                self.logger.warning("Verification step removed ALL findings. Check verification logic in patcha/utils/verification.py.")
            self.logger.tool_complete("Verification")

            # --- Score findings ---
            self.logger.tool_start("Scoring")
            self.security_score = self.scorer.calculate_score(self.findings)
            score_display = f"{self.security_score:.1f}/10.0" if self.security_score is not None else "N/A"
            self.logger.info(f"Calculated Security Score: {score_display}")
            self.logger.tool_complete("Scoring")

            # --- Generate reports ---
            self.logger.tool_start("Report Generation")
            json_report_path: Optional[Path] = None
            html_report_path: Optional[Path] = None
            sarif_report_path: Optional[Path] = None

            # Save the primary findings summary (patcha.json)
            try:
                # self.output_path is already set to patcha.json (or custom name)
                # Ensure findings have a to_dict method or use __dict__
                findings_dict_list = [finding.to_dict() for finding in self.findings]
                report_data = {
                    "scan_timestamp": datetime.now().isoformat(),
                    "repository_path": str(self.repo_path),
                    "security_score": self.security_score,
                    "findings_count": len(self.findings),
                    "findings": findings_dict_list
                }
                with open(self.output_path, 'w', encoding='utf-8') as f:
                    json.dump(report_data, f, indent=2) # Use indent=2 for consistency
                self.logger.info(f"JSON report saved to: {self.output_path}")
                json_report_path = self.output_path
            except Exception as e:
                 self.logger.error(f"Failed to save JSON report to {self.output_path}: {e}", exc_info=True)


            # Generate detailed HTML report (patcha.html) if ReportGenerator is available
            if self.report_generator:
                try:
                    # Derive HTML path from JSON path (e.g., patcha.json -> patcha.html)
                    html_filename = self.base_filename + ".html"
                    html_report_path_obj = self.output_path.with_name(html_filename)

                    # Call the HTML report generation method
                    generated_html_path = self.report_generator.generate_report(
                        self.findings,
                        self.output_path.parent, # Pass the output directory
                        "html",
                        self.security_score
                    )
                    if generated_html_path:
                        # Rename generated file if necessary (generate_report creates timestamped name)
                        # Or adjust generate_report to accept the exact output path
                        # For now, assume generate_report creates the correct file or we adjust it later
                        # Let's assume generate_report needs adjustment to write to a specific path
                        # We'll call the internal method directly for now for simplicity here:
                        html_report_path = self.report_generator._generate_html_report(
                             self.findings, html_report_path_obj, self.security_score
                        )
                        if html_report_path:
                            self.logger.info(f"HTML report generated: {html_report_path}")
                        else:
                            self.logger.error(f"HTML report generation method failed.")
                    else:
                         self.logger.error(f"HTML report generation failed.")


                except AttributeError as ae:
                     self.logger.error(f"HTML Report generation failed: {ae}. Ensure methods exist in ReportGenerator.")
                     self.logger.debug("Traceback:", exc_info=True)
                except Exception as e:
                    self.logger.error(f"Failed to generate HTML report: {e}", exc_info=True)

                # --- Generate SARIF report (patcha.sarif) ---
                try:
                    # Derive SARIF path (e.g., patcha.json -> patcha.sarif)
                    sarif_filename = self.base_filename + ".sarif"
                    sarif_report_path_obj = self.output_path.with_name(sarif_filename)

                    # Call the SARIF report generation method (add this to ReportGenerator)
                    sarif_report_path = self.report_generator._generate_sarif_report(
                         self.findings, sarif_report_path_obj # Pass findings and target path
                    )
                    if sarif_report_path:
                        self.logger.info(f"SARIF report generated: {sarif_report_path}")
                    else:
                        self.logger.error(f"SARIF report generation method failed.")

                except AttributeError as ae:
                     self.logger.error(f"SARIF Report generation failed: {ae}. Ensure _generate_sarif_report method exists in ReportGenerator.")
                     self.logger.debug("Traceback:", exc_info=True)
                except Exception as e:
                    self.logger.error(f"Failed to generate SARIF report: {e}", exc_info=True)

            else:
                self.logger.warning("ReportGenerator not available, skipping HTML and SARIF report generation.")

            self.logger.tool_complete("Report Generation")

            # Log final summary using the logger method
            self.logger.final_summary(
                self.findings,
                self.security_score,
                json_report_path, # Pass the primary JSON path
                html_report_path, # Pass the HTML path if generated
                sarif_report_path # Pass the SARIF path if generated
            )

        except Exception as e:
            self.logger.error(f"An unexpected error occurred during the scan process: {e}", exc_info=True)
            # Log a final failure message if the whole process crashes
            self.logger.critical("Scan process failed.")

    # --- Helper methods like _get_severity_counts are now in PatchaLogger ---
    # def _get_severity_counts(self, findings: List[SecurityFinding]) -> Dict[str, int]:
    #     ... (Removed from here) ...

    # def _should_run_phase(self, phase_name: str, target_url: Optional[str]) -> bool:
    #     """Determine if a scan phase should run based on configuration."""
    #     if phase_name == "Nikto" and not target_url:
    #         self.logger.info("Skipping Nikto scan: No target URL provided.")
    #         return False
    #     # Add other conditions if needed
    #     return True

def main():
    parser = argparse.ArgumentParser(description="Patcha Security Scanner")
    parser.add_argument("repo_path", help="Path to the repository to scan")
    # --- Keep the default as None here, handle default name in __init__ ---
    parser.add_argument("--output", "-o", default=None, help="Output file name for findings summary (default: shield.json in repo root)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging (DEBUG level)")
    parser.add_argument("--target-url", "-u", help="Target URL for DAST scanning (if implemented)")

    args = parser.parse_args()

    if args.verbose:
        # Set root logger level if using basicConfig elsewhere, otherwise set patcha logger level
        logging.getLogger("patcha").setLevel(logging.DEBUG)
        # Or if basicConfig is the main config: logging.getLogger().setLevel(logging.DEBUG)

    try:
        # Pass the output argument to the constructor
        scanner = SecurityScanner(args.repo_path, output_file=args.output, verbose=args.verbose)
        scanner.scan(args.target_url)
        # --- Use the path stored in the scanner instance for the final message ---
        print(f"Scan complete. Results saved to {scanner.output_path}")
        # Determine HTML path for final message if generated
        html_path = scanner.output_path.with_suffix(".html")
        if html_path.exists():
             print(f"HTML report saved to {html_path}")

    except Exception as e:
        # Use the configured logger to report the final error
        logger.critical(f"Scan failed: {str(e)}", exc_info=True) # Log full traceback for critical failures
        sys.exit(1)

if __name__ == "__main__":
    main()