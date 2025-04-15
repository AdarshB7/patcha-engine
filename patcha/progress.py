import logging
from typing import Optional
from rich.progress import Progress, TaskID
from rich.console import Console

logger = logging.getLogger("patcha")

class ProgressTracker:
    """Track progress of security scans"""
    
    def __init__(self, console: Console):
        self.console = console
        self.progress: Optional[Progress] = None
    
    def create_progress(self) -> Progress:
        """Create and return a progress bar using the shared console"""
        self.progress = Progress(
            *Progress.get_default_columns(),
            console=self.console,
            transient=True
        )
        return self.progress
    
    def update_progress(self, task_id: TaskID, advance: float = 1, description: Optional[str] = None) -> None:
        """Update a progress bar"""
        if self.progress:
            update_kwargs = {"advance": advance}
            if description is not None:
                update_kwargs["description"] = description
            self.progress.update(task_id, **update_kwargs)
        else:
            logger.warning("Attempted to update progress before it was created.")

    # Optional: Add a method to explicitly stop/finish the progress bar if needed
    # def stop_progress(self):
    #     if self.progress:
    #         self.progress.stop()
    #         self.progress = None 