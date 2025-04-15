import logging
from rich.console import Console
from rich.logging import RichHandler
from typing import Optional, Any, List, Dict
from pathlib import Path
from .findings import SecurityFinding

class PatchaLogger:
    """Custom logger for Patcha"""
    
    def __init__(self, verbose: bool = False):
        self.console = Console()
        self.verbose = verbose
        
        # Configure logging
        # Only show INFO+ for non-verbose, DEBUG+ for verbose
        level = logging.DEBUG if verbose else logging.INFO
        # Use a simpler format, especially for non-verbose
        log_format = "%(asctime)s - %(levelname)s - %(message)s" if verbose else "%(message)s"
        logging.basicConfig(
            level=level,
            format=log_format,
            datefmt="[%X]",
            # Only use RichHandler for verbose mode to keep non-verbose minimal
            # For non-verbose, basic handler might be sufficient or even preferred
            handlers=[RichHandler(rich_tracebacks=True, console=self.console, show_path=verbose)] if verbose else [logging.StreamHandler()]
        )
        
        self.logger = logging.getLogger("patcha")
        # If not verbose, prevent lower-level loggers (like scanners) from outputting INFO
        if not verbose:
             # Set level specifically for the 'patcha' logger if basicConfig affects root
             self.logger.setLevel(logging.WARNING) # Show WARNING, ERROR, CRITICAL by default
             # Or, iterate through existing handlers and set their level if needed

    def start_scan(self, repo_path: str) -> None:
        """Log the start of a scan"""
        # Use print for the very first message, independent of logging level
        self.console.print(f"Starting security scan for: {repo_path}...")
    
    def tool_start(self, tool_name: str) -> None:
        """Log the start of a tool/phase only at DEBUG level"""
        # Only log this if verbose mode is enabled
        self.logger.debug(f"Running {tool_name}...")
    
    def tool_complete(self, tool_name: str, findings_count: Optional[int] = None) -> None:
        """Log the completion of a tool/phase only at DEBUG level"""
        # Only log this if verbose mode is enabled
        self.logger.debug(f"{tool_name} completed.")
    
    def tool_error(self, tool_name: str, error: str) -> None:
        """Log an error from a tool at ERROR level (will always show)"""
        self.logger.error(f"Error during {tool_name}: {error}")
    
    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log 'msg % args' with severity 'DEBUG'."""
        # This will only show if verbose = True
        self.logger.debug(msg, *args, **kwargs)
    
    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log 'msg % args' with severity 'INFO'."""
        # This will generally NOT show unless verbose = True due to logger level setting
        self.logger.info(msg, *args, **kwargs)
    
    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log 'msg % args' with severity 'WARNING'."""
        # This will show by default
        self.logger.warning(msg, *args, **kwargs)
    
    def error(self, msg: str, *args: Any, exc_info: Any = None, **kwargs: Any) -> None:
        """Log 'msg % args' with severity 'ERROR'."""
        # This will show by default
        self.logger.error(msg, *args, exc_info=exc_info, **kwargs)
    
    def critical(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log 'msg % args' with severity 'CRITICAL'."""
        # This will show by default
        self.logger.critical(msg, *args, **kwargs)
    
    def final_summary(self, findings: List[SecurityFinding], score: Optional[float], output_path: Path, json_report_path: Optional[Path], html_report_path: Optional[Path]):
        """Logs the final scan summary (simplified)."""
        # Use print for the final summary for guaranteed visibility
        self.console.print("-" * 40)
        self.console.print("Scan complete.")
        score_display = f"{score:.1f}/10.0" if score is not None else "N/A"
        self.console.print(f"Calculated Security Score: {score_display}")
        # output_path is the primary JSON (shield.json)
        self.console.print(f"Findings Summary: {output_path}")
        # json_report_path is None based on previous changes, so skip
        if html_report_path and html_report_path.exists():
            self.console.print(f"HTML Report: {html_report_path}")
        self.console.print("-" * 40)

    def _get_severity_counts(self, findings: List[SecurityFinding]) -> Dict[str, int]:
        """Helper to count findings by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            severity = str(getattr(finding, 'severity', 'info')).lower()
            if severity in counts:
                counts[severity] += 1
            else:
                counts["info"] += 1
                self.logger.warning(f"Finding with unknown severity '{severity}' counted as 'info'.") # Keep warning
        return counts 