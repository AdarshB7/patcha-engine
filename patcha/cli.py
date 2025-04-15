#!/usr/bin/env python3
import sys
import logging
import typer
from pathlib import Path
from typing import Optional
from .bulk import SecurityScanner

app = typer.Typer()
logger = logging.getLogger("patcha")

@app.command()
def scan(
    path: str = typer.Argument(..., help="Path to the repository to scan"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    target_url: Optional[str] = typer.Option(None, "--url", "-u", help="Target URL for web scans")
):
    """Scan a repository for security issues"""
    try:
        scanner = SecurityScanner(path, output, verbose)
        scanner.scan(target_url)
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        sys.exit(1)

def main():
    """Main entry point for the CLI"""
    try:
        app()
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 