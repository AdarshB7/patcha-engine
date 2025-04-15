import os
import logging
from pathlib import Path
from typing import List, Set
from datetime import datetime

logger = logging.getLogger("patcha")

class FileUtils:
    """Utility class for file operations"""
    
    def __init__(self, repo_path: Path):
        if not isinstance(repo_path, Path):
            raise TypeError(f"Expected repo_path to be a Path object, got {type(repo_path)}")
        self.repo_path = repo_path
        logger.debug(f"FileUtils initialized with repo path: {self.repo_path}")
    
    def is_text_file(self, file_path: str) -> bool:
        """Check if a file is a text file"""
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                return b'\0' not in chunk  # Binary files typically contain null bytes
        except:
            return False
    
    def should_scan_file(self, file_path: str) -> bool:
        """Determine if a file should be scanned"""
        # Skip binary and very large files
        skip_extensions = {
            '.pyc', '.pyo', '.so', '.dll', '.class',
            '.jpg', '.jpeg', '.png', '.gif', '.ico',
            '.mp3', '.mp4', '.avi', '.mov', '.zip',
            '.tar', '.gz', '.rar'
        }
        
        try:
            # Skip files larger than 10MB
            if os.path.getsize(file_path) > 10_000_000:
                return False
            
            # Skip files with binary extensions
            if any(file_path.lower().endswith(ext) for ext in skip_extensions):
                return False
            
            # Skip files in common directories that often have false positives
            rel_path = os.path.relpath(file_path, self.repo_path)
            if any(p in rel_path for p in ['node_modules/', 'vendor/', 'dist/', 'build/', 'test/fixtures/']):
                return False
            
            return True
        except OSError:
            return False
    
    def get_scannable_files(self) -> List[str]:
        """Get list of files that should be scanned"""
        scannable_files = []
        for root, _, files in os.walk(self.repo_path):
            # Skip hidden directories
            if '/.' in root:
                continue
            
            for file in files:
                file_path = os.path.join(root, file)
                if self.should_scan_file(file_path):
                    scannable_files.append(file_path)
        return scannable_files
    
    def get_modified_files(self) -> Set[str]:
        """Get list of files modified since last scan"""
        shield_path = self.repo_path / "shield.json"
        if not shield_path.exists():
            return set(self.get_scannable_files())
            
        try:
            with open(shield_path) as f:
                last_scan = json.load(f)
                last_scan_time = datetime.fromisoformat(last_scan["scan_info"]["scan_time"])
                
            modified_files = set()
            for file_path in self.get_scannable_files():
                try:
                    if datetime.fromtimestamp(os.path.getmtime(file_path)) > last_scan_time:
                        modified_files.add(file_path)
                except OSError:
                    modified_files.add(file_path)
                    
            return modified_files
        except (json.JSONDecodeError, KeyError, ValueError):
            return set(self.get_scannable_files())
    
    def get_git_modified_files(self) -> Set[str]:
        """Get list of files modified since last commit using Git"""
        import subprocess
        try:
            result = subprocess.run(
                ["git", "-C", str(self.repo_path), "diff", "--name-only", "HEAD"],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                modified_files = set()
                for file in result.stdout.splitlines():
                    file_path = os.path.join(self.repo_path, file)
                    if os.path.exists(file_path) and self.should_scan_file(file_path):
                        modified_files.add(file_path)
                return modified_files
            else:
                logger.warning("Failed to get modified files from Git. Falling back to all files.")
                return set(self.get_scannable_files())
        except Exception as e:
            logger.warning(f"Error getting Git modified files: {str(e)}. Falling back to all files.")
            return set(self.get_scannable_files())
    
    def get_all_files(self, extensions: List[str] = None) -> List[Path]:
        """Get all files in the repository with specified extensions"""
        if not extensions:
            extensions = ['.py', '.js', '.ts', '.java', '.php', '.rb', '.go', '.c', '.cpp', '.h', '.hpp']
        
        files = []
        for ext in extensions:
            files.extend(list(self.repo_path.glob(f"**/*{ext}")))
        
        # Filter out files in common directories to ignore
        ignore_dirs = ['node_modules', 'venv', '.git', '.vscode', '__pycache__', 'build', 'dist']
        return [f for f in files if not any(ignore_dir in str(f) for ignore_dir in ignore_dirs)]
    
    def get_file_content(self, file_path: Path) -> str:
        """Get the content of a file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            logger.debug(f"Error reading file {file_path}: {str(e)}")
            return ""
    
    def get_file_lines(self, file_path: Path) -> List[str]:
        """Get the lines of a file"""
        content = self.get_file_content(file_path)
        return content.splitlines()
    
    def get_file_extension(self, file_path: Path) -> str:
        """Get the extension of a file"""
        return os.path.splitext(file_path)[1].lower()
    
    def is_binary_file(self, file_path: Path) -> bool:
        """Check if a file is binary"""
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                return b'\0' in chunk
        except Exception:
            return False
    
    def get_file_type(self, file_path: Path) -> str:
        """Get the type of a file based on its extension"""
        ext = self.get_file_extension(file_path)
        
        if ext in ['.py']:
            return 'python'
        elif ext in ['.js', '.ts', '.jsx', '.tsx']:
            return 'javascript'
        elif ext in ['.java']:
            return 'java'
        elif ext in ['.php']:
            return 'php'
        elif ext in ['.rb']:
            return 'ruby'
        elif ext in ['.go']:
            return 'go'
        elif ext in ['.c', '.cpp', '.h', '.hpp']:
            return 'c'
        elif ext in ['.html', '.htm']:
            return 'html'
        elif ext in ['.css']:
            return 'css'
        elif ext in ['.json']:
            return 'json'
        elif ext in ['.xml']:
            return 'xml'
        elif ext in ['.yaml', '.yml']:
            return 'yaml'
        elif ext in ['.md']:
            return 'markdown'
        else:
            return 'unknown' 