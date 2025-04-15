from setuptools import setup, find_packages

setup(
    name="patcha",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "semgrep>=1.0.0",
        "bandit>=1.7.0",
        "truffleHog>=2.2.1",
        "jinja2>=3.0.0",
        "rich>=10.0.0",  # For pretty console output
        "typer>=0.4.0",  # For CLI interface
        "pyyaml>=6.0",   # For configuration files
        "requests>=2.25.0",  # For API calls
    ],
    entry_points={
        "console_scripts": [
            "patcha=patcha.cli:main",
        ],
    },
    description="A security scanner for code repositories",
    author="Patcha Team",
    author_email="info@patcha.dev",
    url="https://github.com/patcha/patcha",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.8",
) 