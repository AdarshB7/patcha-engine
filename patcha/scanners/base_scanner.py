import logging
import subprocess
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from ..findings import FindingsManager, SecurityFinding

logger = logging.getLogger("patcha")

class BaseScanner:
    """Base class for all security scanners"""
    
    def __init__(self, repo_path: Path, findings_manager: FindingsManager):
        if not isinstance(repo_path, Path):
            raise TypeError(f"Expected repo_path to be a Path object, got {type(repo_path)}")
        if not isinstance(findings_manager, FindingsManager):
             raise TypeError(f"Expected findings_manager to be a FindingsManager object, got {type(findings_manager)}")

        self.repo_path = repo_path
        self.findings_manager = findings_manager
        self.name = self.__class__.__name__
        logger.debug(f"{self.__class__.__name__} initialized for repo: {self.repo_path}")
    
    def scan(self, *args, **kwargs) -> None:
        """Run the specific scanner implementation"""
        # This method should be implemented by subclasses
        raise NotImplementedError("Subclasses must implement the scan method")
    
    def check_tool_installed(self, tool_name: str) -> bool:
        """Check if a command-line tool is installed"""
        return shutil.which(tool_name) is not None
    
    def run_subprocess(self, command: List[str], timeout: int = 300) -> Optional[subprocess.CompletedProcess]:
        """Run a subprocess command and return the result"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {timeout} seconds: {' '.join(command)}")
            return None
        except Exception as e:
            logger.error(f"Error running command {' '.join(command)}: {str(e)}")
            return None
    
    def add_finding(self, finding: SecurityFinding) -> None:
        """Add a pre-created finding object to the findings manager"""
        try:
            # Input is already a SecurityFinding object, no need to create another one
            if not isinstance(finding, SecurityFinding):
                logger.error(f"Attempted to add non-SecurityFinding object: {type(finding)}")
                return # Or raise an error

            # Add the received finding object directly to the manager
            self.findings_manager.add_finding(finding)
            # Keep the debug log if useful
            # logger.debug(f"Added finding via BaseScanner: {finding.title}")

        except Exception as e:
            # Log any unexpected errors during the addition process
            logger.error(f"Error adding finding in BaseScanner: {str(e)}", exc_info=True)
    
    # Optional: Keep a method to get findings directly if needed by scanners
    # def get_findings(self) -> List[SecurityFinding]:
    #     """Get findings currently held by the manager"""
    #     return self.findings_manager.get_findings() 