# 🔒 Smart Contract Security Scanner

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Solidity](https://img.shields.io/badge/Solidity-0.4.x%20to%200.8.x-777777?logo=solidity)](https://soliditylang.org)

Static analysis tool for detecting security vulnerabilities in Solidity smart contracts. Built for developers and security auditors to identify common weaknesses before deployment.

> ⚠️ **SECURITY NOTICE**: This tool performs **static analysis only** and may produce false positives/negatives. Always combine with professional audits, manual review, and runtime testing tools (Slither, Mythril, Echidna).

## ✨ Features

- 🔍 **12+ Vulnerability Checks** including:
  - Reentrancy (SWC-107)
  - tx.origin misuse (SWC-115)
  - Integer overflow/underflow (SWC-101)
  - Access control issues (SWC-105)
  - Timestamp dependence (SWC-116)
  - Dangerous delegatecall (SWC-112)
  - Unprotected selfdestruct (SWC-106)
  - Unchecked external calls
  - Vulnerable compiler versions
- 📊 **Severity Classification**: Critical, High, Medium, Low, Info, Gas Optimization
- 💡 **Actionable Remediation**: Detailed mitigation steps + OpenZeppelin examples
- 📈 **Rich Console Output**: Color-coded findings with confidence scores
- 📤 **Multiple Export Formats**: JSON, HTML reports
- ⚡ **Gas Optimization Checks** (deep analysis mode)
- 🔍 **SWC Registry Integration**: Standardized weakness classification

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Solidity project directory or `.sol` files

### Installation

```bash
# Clone repository (optional)
git clone https://github.com/your-username/smartcontractsecscan.git
cd smartcontractsecscan

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # Linux/MacOS
# OR
venv\Scripts\activate     # Windows
```

Basic Usage
```bash
# Scan a single contract
python smartcontractsecscan.py contracts/MyToken.sol

# Scan entire project directory
python smartcontractsecscan.py ./contracts

# Deep analysis (gas optimization + best practices)
python smartcontractsecscan.py ./contracts --deep

# Generate JSON report
python smartcontractsecscan.py ./contracts --output report.json

# Generate HTML report
python smartcontractsecscan.py ./contracts --output report.html

# Custom ignore patterns
python smartcontractsecscan.py ./src --ignore 'test' --ignore 'mock'
```

Example Output
```bash
┌──────────────────────────────────────────────────────────────┐
│                    Scan Complete                             │
│ Path: ./contracts                                            │
│ Duration: 2.34s                                              │
│ Files: 12 | Contracts: 8                                     │
└──────────────────────────────────────────────────────────────┘

Summary:
┌──────────────────────┬────────┐
│ Severity             │ Count  │
├──────────────────────┼────────┤
│ CRITICAL             │ 1      │
│ HIGH                 │ 3      │
│ MEDIUM               │ 2      │
│ LOW                  │ 4      │
│ INFO                 │ 2      │
│ GAS OPTIMIZATION     │ 5      │
└──────────────────────┴────────┘

Findings by File:
./contracts/Vault.sol (3 findings)
  [CRITICAL] Line 45: Potential Reentrancy Vulnerability
     Confidence: 70%
     payable(recipient).transfer(amount);
     SWC-107: Reentrancy
```

🔐 Security Disclaimer

This tool is for educational and authorized security testing purposes only.

❌ DO NOT use on contracts you don't own without explicit permission

❌ DO NOT rely solely on static analysis for production security

✅ ALWAYS combine with:

Professional security audits

Runtime testing (Slither, Mythril, Echidna)

Extensive test coverage (>95%)

Testnet deployment before mainnet

⚠️ Author assumes NO LIABILITY for undetected vulnerabilities or misuse
