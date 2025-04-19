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
        log_format = "%(message)s" if verbose else "%(message)s"
        
        # Configure the root logger
        logging.basicConfig(
            level=level,
            format=log_format,
            datefmt="[%X]",
            handlers=[logging.StreamHandler()]  # Simpler handler
        )
        
        # Get the patcha logger
        self.logger = logging.getLogger("patcha")
        
        # Set the level for the patcha logger
        if verbose:
            # Even in verbose mode, filter out repetitive messages
            self.logger.setLevel(logging.INFO)  # Only show INFO and above by default
            
            # Create a filter to suppress repetitive debug messages
            class RepetitiveFilter(logging.Filter):
                def __init__(self):
                    super().__init__()
                    self.seen_patterns = set()
                    
                def filter(self, record):
                    # Skip repetitive "Added finding" and "Severity metadata missing" messages
                    if "Added finding:" in record.getMessage() or "Severity metadata missing" in record.getMessage():
                        return False
                    return True
            
            # Apply the filter to the logger
            self.logger.addFilter(RepetitiveFilter())
        else:
            # In non-verbose mode, only show warnings and above
            self.logger.setLevel(logging.WARNING)
            
            # Also set all other loggers to WARNING level
            for name in logging.root.manager.loggerDict:
                if name != "patcha":
                    logging.getLogger(name).setLevel(logging.WARNING)

    def start_scan(self, repo_path: str) -> None:
        """Log the start of a scan"""
        # Use print for the very first message, independent of logging level
        self.console.print(f"Starting security scan for: {repo_path}...")
    
    def tool_start(self, tool_name: str) -> None:
        """Log the start of a tool's execution."""
        if self.verbose:
            self.logger.info(f"Starting {tool_name} scan...")
        else:
            # In non-verbose mode, just print a simple indicator
            self.console.print(f"[bold blue]▶ Running {tool_name}...[/bold blue]")
    
    def tool_complete(self, tool_name: str) -> None:
        """Log the successful completion of a tool's execution."""
        if self.verbose:
            self.logger.info(f"{tool_name} scan completed successfully.")
        else:
            # In non-verbose mode, use a checkmark
            self.console.print(f"[bold green]✓ {tool_name} completed[/bold green]")
    
    def tool_error(self, tool_name: str, error_message: str) -> None:
        """Log an error that occurred during a tool's execution."""
        self.logger.error(f"{tool_name}: {error_message}")
        # Always show errors, even in non-verbose mode
        self.console.print(f"[bold red]✗ {tool_name} error: {error_message}[/bold red]")
    
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
    
    def final_summary(self, findings: List[SecurityFinding], score: Optional[float],
                      json_report_path: Optional[Path],
                      html_report_path: Optional[Path],
                      sarif_report_path: Optional[Path]):
        """Logs the final scan summary."""
        # Use rich formatting for a nicer summary
        self.console.print("\n[bold cyan]═════════════════════════════════════════[/bold cyan]")
        self.console.print("[bold cyan]🔍 SCAN COMPLETE[/bold cyan]")
        
        # Security score with color based on value
        score_display = f"{score:.1f}/10.0" if score is not None else "N/A"
        score_color = "green" if score and score >= 7.0 else "yellow" if score and score >= 4.0 else "red"
        self.console.print(f"[bold]Security Score:[/bold] [bold {score_color}]{score_display}[/bold {score_color}]")
        
        # Findings summary
        self.console.print(f"[bold]Total Findings:[/bold] {len(findings)}")
        
        # Report paths
        if json_report_path:
            if isinstance(json_report_path, str):
                json_report_path = Path(json_report_path)
            
            if json_report_path.exists():
                self.console.print(f"[bold]JSON Report:[/bold] {json_report_path}")

        if html_report_path:
            if isinstance(html_report_path, str):
                html_report_path = Path(html_report_path)
            
            if html_report_path.exists():
                self.console.print(f"[bold]HTML Report:[/bold] {html_report_path}")
        
        if sarif_report_path:
            if isinstance(sarif_report_path, str):
                sarif_report_path = Path(sarif_report_path)
            
            if sarif_report_path.exists():
                self.console.print(f"[bold]SARIF Report:[/bold] {sarif_report_path}")

        self.console.print("[bold cyan]═════════════════════════════════════════[/bold cyan]\n")

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