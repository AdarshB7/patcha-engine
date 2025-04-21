# 🛡️: Patcha AI

*AI‑native security scanner that feeds vulnerability fixes straight to your AI code editor.*

## Why Patcha?

Traditional static scanners stop at **"here’s a vulnerability"**. Patcha goes one step further—producing an AI‑optimised report your code editor (Cursor, VS Code Copilot, etc.) can use to **auto‑remediate** issues. Ship faster, stay secure.

## ✨: Features

| Category               | Details                                                                               |
| ---------------------- | ------------------------------------------------------------------------------------- |
| 🧠: **AI‑ready report** | Outputs `shield.json` + SARIF so LLMs can consume structured vulnerability data.      |
| 🔍: **Deep scanning**   | Combines Semgrep rules, Trivy, secret‑detection & licence checks into a single pass.  |
| ⚡: **Fast**             | Multithreaded engine; scans 1000 files in < 30 s on a MacBook M2.                     |
| 🚀: **Plug‑and‑play**   | One command (`patcha .`)—no config required for the first run.                        |
| 🛡️: **Upcoming**       | LLM‑enhanced false‑positive reduction, dynamic analysis sandbox, MCP agent hardening. |


## Installation

```bash
pip install patcha
```

> **Prereqs:** Python 3.9+, macOS/Linux. Windows users can run via WSL2.

## Quick Start

```bash
# 1. Scan your repo
patcha ./my‑project

# 2. Open shield.json with Cursor (or your favourite AI editor)

# 3. Accept fix suggestions & ship 🚀
```

Example output (truncated):

```jsonc
{
  "file": "src/payments.py",
  "line": 87,
  "rule": "sql‑injection",
  "severity": "HIGH",
  "message": "User‑controlled input flows into raw SQL query.",
  "fix": "Use parameterised queries via the DB driver."
}
```
## 📅 Product Roadmap

### 🎯 Current (Available Now)
- AI Optimized Analysis
  - Code Analysis and Best Practices optimized for AI Digestion
  - Vulnerability detection
  - CLI Tool integration

### 🔜 Upcoming
- LLM Enhanced Scanning
  - Analysis powered by AI with codebase context
  - False Positive Reduction
  - MCP Server Validation and Integration for AI Agents

### 📋 Planned
- Dynamic Analysis & Threat Modeling
  - Business Logic Vulnerability Detection
  - Dynamic Code Analysis via LLM
  - Threat Modeling and Mitigation

## 🤝 Contributing

We welcome contributions from the community! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 💬 Community

Join our community to stay updated and get help:

- [Discord Server](https://discord.gg/aBKCQxRPDb)
- [Email](patchasec@gmail.com)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
