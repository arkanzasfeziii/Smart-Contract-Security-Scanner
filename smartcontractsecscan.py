#!/usr/bin/env python3
"""
Smart Contract Security Scanner - Static analysis tool for Solidity smart contracts.

This tool performs comprehensive static analysis of Solidity smart contracts to identify
common vulnerabilities, security risks, and best practice violations.

Author: arkanzasfeziii
License: MIT
"""

# === Imports ===
import argparse
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, field_validator
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

# === Constants ===
VERSION = "1.0.0"
AUTHOR = "arkanzasfeziii"
TOOL_NAME = "Smart Contract Security Scanner"

# Security warning
SECURITY_WARNING = """
⚠️  SECURITY NOTICE ⚠️

This tool performs STATIC ANALYSIS only and may produce false positives/negatives.
It is designed for authorized security testing and code review of YOUR OWN contracts.

Important limitations:
- Static analysis cannot detect all runtime vulnerabilities
- Manual code review and formal verification are essential
- Always combine with professional audits and tools like Slither/Mythril
- Test thoroughly on testnets before mainnet deployment

By using this tool, you acknowledge that:
- This is for authorized code review and security testing
- You understand its limitations
- The author (arkanzasfeziii) assumes NO LIABILITY for misuse or undetected vulnerabilities

"""

# File extensions to scan
SOLIDITY_EXTENSIONS = {'.sol'}

# Default ignore patterns
DEFAULT_IGNORE_PATTERNS = [
    r'node_modules',
    r'\.git',
    r'build',
    r'artifacts',
    r'cache',
    r'coverage',
]

# Vulnerable Solidity compiler versions
VULNERABLE_VERSIONS = {
    '0.4.': 'Version 0.4.x has multiple known vulnerabilities. Upgrade to 0.8.0+',
    '0.5.': 'Version 0.5.x lacks built-in overflow protection. Consider 0.8.0+',
    '0.6.': 'Version 0.6.x lacks built-in overflow protection. Consider 0.8.0+',
    '0.7.': 'Version 0.7.x lacks built-in overflow protection. Consider 0.8.0+',
}

# SWC (Smart Contract Weakness Classification) mappings
SWC_REGISTRY = {
    'SWC-107': 'Reentrancy',
    'SWC-115': 'Authorization through tx.origin',
    'SWC-101': 'Integer Overflow and Underflow',
    'SWC-105': 'Unprotected Ether Withdrawal',
    'SWC-106': 'Unprotected SELFDESTRUCT Instruction',
    'SWC-116': 'Timestamp Dependence',
    'SWC-120': 'Weak Sources of Randomness',
    'SWC-128': 'DoS with Block Gas Limit',
    'SWC-112': 'Delegatecall to Untrusted Callee',
}

# === Enums ===
class Severity(Enum):
    """Severity levels for findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    GAS = "GAS_OPTIMIZATION"

class VulnerabilityType(Enum):
    """Types of smart contract vulnerabilities."""
    REENTRANCY = "Reentrancy"
    ACCESS_CONTROL = "Access Control"
    ARITHMETIC = "Arithmetic Issues"
    UNCHECKED_CALL = "Unchecked External Call"
    TX_ORIGIN = "tx.origin Usage"
    TIMESTAMP_DEPENDENCE = "Timestamp Dependence"
    DANGEROUS_DELEGATECALL = "Dangerous Delegatecall"
    SELFDESTRUCT = "Unprotected Selfdestruct"
    GAS_ISSUES = "Gas Optimization"
    COMPILER_VERSION = "Compiler Version"
    BEST_PRACTICES = "Best Practices"

# === Data Models ===
@dataclass
class Finding:
    """Represents a security finding."""
    title: str
    severity: Severity
    vuln_type: VulnerabilityType
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    confidence: int = 0  # 0-100
    mitigation: Optional[str] = None
    swc: Optional[str] = None
    references: List[str] = field(default_factory=list)
    gas_impact: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "title": self.title,
            "severity": self.severity.value,
            "vulnerability_type": self.vuln_type.value,
            "description": self.description,
            "file_path": str(self.file_path),
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "confidence": self.confidence,
            "mitigation": self.mitigation,
            "swc": self.swc,
            "references": self.references,
            "gas_impact": self.gas_impact,
            "timestamp": self.timestamp.isoformat()
        }

@dataclass
class ScanResult:
    """Container for all scan results."""
    scan_path: str
    scan_start: datetime
    scan_end: Optional[datetime] = None
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    contracts_found: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to results."""
        self.findings.append(finding)

    def get_summary(self) -> Dict[str, int]:
        """Get summary statistics."""
        summary = {
            "total": len(self.findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "gas": 0,
            "files_scanned": self.files_scanned,
            "contracts_found": self.contracts_found
        }
        for finding in self.findings:
            severity_key = finding.severity.value.lower().replace('_', '')
            if severity_key.startswith('gas'):
                summary['gas'] += 1
            elif severity_key in summary:
                summary[severity_key] += 1
        return summary

    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            "scan_path": self.scan_path,
            "scan_start": self.scan_start.isoformat(),
            "scan_end": self.scan_end.isoformat() if self.scan_end else None,
            "summary": self.get_summary(),
            "findings": [f.to_dict() for f in self.findings],
            "files_scanned": self.files_scanned,
            "contracts_found": self.contracts_found,
            "metadata": self.metadata
        }

# === Utility Functions ===
def setup_logging(verbose: bool = False) -> logging.Logger:
    """
    Configure logging for the application.

    Args:
        verbose: Enable verbose logging

    Returns:
        Configured logger instance
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('smartcontractsecscan.log'),
            logging.StreamHandler(sys.stderr) if verbose else logging.NullHandler()
        ]
    )
    return logging.getLogger(__name__)

def should_ignore_path(path: Path, ignore_patterns: List[str]) -> bool:
    """
    Check if path should be ignored based on patterns.

    Args:
        path: Path to check
        ignore_patterns: List of regex patterns to ignore

    Returns:
        True if should be ignored
    """
    path_str = str(path)
    for pattern in ignore_patterns:
        if re.search(pattern, path_str):
            return True
    return False

def extract_pragma_version(content: str) -> Optional[str]:
    """
    Extract Solidity pragma version from contract.

    Args:
        content: Contract source code

    Returns:
        Version string or None
    """
    pragma_pattern = r'pragma\s+solidity\s+([^;]+);'
    match = re.search(pragma_pattern, content)
    if match:
        return match.group(1).strip()
    return None

def parse_solidity_version(version_str: str) -> Optional[str]:
    """
    Parse Solidity version string.

    Args:
        version_str: Version specification (e.g., "^0.8.0", ">=0.6.0 <0.9.0")

    Returns:
        Base version or None
    """
    # Extract numeric version
    version_match = re.search(r'(\d+\.\d+\.\d+)', version_str)
    if version_match:
        return version_match.group(1)
    
    # Extract partial version
    version_match = re.search(r'(\d+\.\d+)', version_str)
    if version_match:
        return version_match.group(1)
    
    return None

# === Vulnerability Detection ===
class SolidityAnalyzer:
    """Analyzes Solidity code for security vulnerabilities."""

    def __init__(
        self,
        deep_analysis: bool = False,
        pragma_check: bool = False,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize Solidity analyzer.

        Args:
            deep_analysis: Enable deep analysis
            pragma_check: Enable pragma version checking
            logger: Logger instance
        """
        self.deep_analysis = deep_analysis
        self.pragma_check = pragma_check
        self.logger = logger or logging.getLogger(__name__)

    def analyze_file(self, file_path: Path) -> List[Finding]:
        """
        Analyze a single Solidity file for vulnerabilities.

        Args:
            file_path: Path to Solidity file

        Returns:
            List of findings
        """
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            # Check pragma version
            if self.pragma_check:
                findings.extend(self._check_pragma_version(file_path, content))

            # Check for reentrancy vulnerabilities
            findings.extend(self._check_reentrancy(file_path, content, lines))

            # Check for tx.origin usage
            findings.extend(self._check_tx_origin(file_path, content, lines))

            # Check for integer overflow/underflow
            findings.extend(self._check_arithmetic_issues(file_path, content, lines))

            # Check for access control issues
            findings.extend(self._check_access_control(file_path, content, lines))

            # Check for timestamp dependence
            findings.extend(self._check_timestamp_dependence(file_path, content, lines))

            # Check for dangerous operations
            findings.extend(self._check_dangerous_operations(file_path, content, lines))

            # Check for unchecked external calls
            findings.extend(self._check_unchecked_calls(file_path, content, lines))

            # Deep analysis checks
            if self.deep_analysis:
                findings.extend(self._check_gas_optimization(file_path, content, lines))
                findings.extend(self._check_best_practices(file_path, content, lines))

        except Exception as e:
            self.logger.error(f"Error analyzing {file_path}: {e}")

        return findings

    def _check_pragma_version(self, file_path: Path, content: str) -> List[Finding]:
        """Check Solidity compiler version."""
        findings = []
        
        pragma_version = extract_pragma_version(content)
        if not pragma_version:
            findings.append(Finding(
                title="Missing Pragma Solidity Version",
                severity=Severity.MEDIUM,
                vuln_type=VulnerabilityType.COMPILER_VERSION,
                description="Contract does not specify Solidity version with pragma",
                file_path=str(file_path),
                line_number=1,
                code_snippet="pragma solidity ^0.8.0;",
                confidence=100,
                mitigation=(
                    "Always specify the Solidity compiler version:\n"
                    "pragma solidity ^0.8.0;\n"
                    "Use a specific version range to ensure consistent compilation."
                ),
                references=[
                    "https://docs.soliditylang.org/en/latest/layout-of-source-files.html#version-pragma"
                ]
            ))
            return findings

        # Check for vulnerable versions
        base_version = parse_solidity_version(pragma_version)
        if base_version:
            for vuln_prefix, warning in VULNERABLE_VERSIONS.items():
                if base_version.startswith(vuln_prefix):
                    findings.append(Finding(
                        title=f"Vulnerable Solidity Version: {pragma_version}",
                        severity=Severity.HIGH,
                        vuln_type=VulnerabilityType.COMPILER_VERSION,
                        description=warning,
                        file_path=str(file_path),
                        line_number=1,
                        code_snippet=f"pragma solidity {pragma_version};",
                        confidence=95,
                        mitigation=(
                            "Update to Solidity 0.8.0 or later for:\n"
                            "- Built-in overflow/underflow protection\n"
                            "- Better error handling\n"
                            "- Improved security features\n"
                            "Recommended: pragma solidity ^0.8.20;"
                        ),
                        swc="SWC-101",
                        references=[
                            "https://blog.soliditylang.org/2020/12/16/solidity-v0.8.0-release-announcement/"
                        ]
                    ))

        return findings

    def _check_reentrancy(self, file_path: Path, content: str, lines: List[str]) -> List[Finding]:
        """Check for reentrancy vulnerabilities."""
        findings = []

        # Pattern: external call followed by state change
        reentrancy_pattern = r'\.call\{|\.transfer\(|\.send\('
        
        for i, line in enumerate(lines, 1):
            if re.search(reentrancy_pattern, line):
                # Check if Checks-Effects-Interactions pattern is followed
                # Look for state changes after external call
                window_start = max(0, i - 1)
                window_end = min(len(lines), i + 10)
                context_lines = lines[window_start:window_end]
                context = '\n'.join(context_lines)

                # Check for state changes after call
                state_change_patterns = [
                    r'\w+\s*=\s*[^=]',  # Assignment
                    r'\w+\s*\+=',       # Increment
                    r'\w+\s*-=',        # Decrement
                    r'\.push\(',        # Array modification
                    r'\.pop\(',
                    r'delete\s+\w+',
                ]

                has_state_change_after = False
                for pattern in state_change_patterns:
                    if re.search(pattern, context):
                        has_state_change_after = True
                        break

                if has_state_change_after or 'call{' in line:
                    findings.append(Finding(
                        title="Potential Reentrancy Vulnerability",
                        severity=Severity.CRITICAL,
                        vuln_type=VulnerabilityType.REENTRANCY,
                        description=(
                            "External call detected that may be vulnerable to reentrancy attack. "
                            "Ensure Checks-Effects-Interactions pattern is followed."
                        ),
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        confidence=70,
                        mitigation=(
                            "Follow Checks-Effects-Interactions pattern:\n"
                            "1. Perform all checks first\n"
                            "2. Update state variables\n"
                            "3. Make external calls last\n\n"
                            "Or use ReentrancyGuard from OpenZeppelin:\n"
                            "import '@openzeppelin/contracts/security/ReentrancyGuard.sol';\n"
                            "contract MyContract is ReentrancyGuard {\n"
                            "    function withdraw() external nonReentrant { ... }\n"
                            "}"
                        ),
                        swc="SWC-107",
                        references=[
                            "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/",
                            "https://swcregistry.io/docs/SWC-107"
                        ]
                    ))

        return findings

    def _check_tx_origin(self, file_path: Path, content: str, lines: List[str]) -> List[Finding]:
        """Check for tx.origin usage."""
        findings = []

        for i, line in enumerate(lines, 1):
            if 'tx.origin' in line:
                findings.append(Finding(
                    title="Dangerous use of tx.origin",
                    severity=Severity.HIGH,
                    vuln_type=VulnerabilityType.TX_ORIGIN,
                    description=(
                        "tx.origin should not be used for authorization. "
                        "It can be manipulated through phishing attacks."
                    ),
                    file_path=str(file_path),
                    line_number=i,
                    code_snippet=line.strip(),
                    confidence=100,
                    mitigation=(
                        "Replace tx.origin with msg.sender:\n\n"
                        "// Bad\n"
                        "require(tx.origin == owner);\n\n"
                        "// Good\n"
                        "require(msg.sender == owner);\n\n"
                        "tx.origin represents the original sender of the transaction chain, "
                        "while msg.sender is the immediate caller."
                    ),
                    swc="SWC-115",
                    references=[
                        "https://swcregistry.io/docs/SWC-115",
                        "https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/tx-origin/"
                    ]
                ))

        return findings

    def _check_arithmetic_issues(self, file_path: Path, content: str, lines: List[str]) -> List[Finding]:
        """Check for integer overflow/underflow issues."""
        findings = []

        pragma_version = extract_pragma_version(content)
        if pragma_version:
            base_version = parse_solidity_version(pragma_version)
            
            # Pre-0.8.0 versions don't have built-in overflow protection
            if base_version and not base_version.startswith('0.8'):
                # Check for SafeMath usage
                has_safemath = 'SafeMath' in content or 'using SafeMath' in content

                if not has_safemath:
                    # Look for arithmetic operations
                    arithmetic_patterns = [r'\+\+', r'--', r'\+=', r'-=', r'\*=', r'/=']
                    
                    for i, line in enumerate(lines, 1):
                        for pattern in arithmetic_patterns:
                            if re.search(pattern, line) and not line.strip().startswith('//'):
                                findings.append(Finding(
                                    title="Potential Integer Overflow/Underflow",
                                    severity=Severity.HIGH,
                                    vuln_type=VulnerabilityType.ARITHMETIC,
                                    description=(
                                        f"Arithmetic operation in Solidity {pragma_version} without SafeMath. "
                                        "This can lead to integer overflow/underflow."
                                    ),
                                    file_path=str(file_path),
                                    line_number=i,
                                    code_snippet=line.strip(),
                                    confidence=80,
                                    mitigation=(
                                        "Use SafeMath library or upgrade to Solidity 0.8.0+:\n\n"
                                        "// Option 1: Use SafeMath (pre-0.8.0)\n"
                                        "import '@openzeppelin/contracts/utils/math/SafeMath.sol';\n"
                                        "using SafeMath for uint256;\n"
                                        "uint256 result = a.add(b);\n\n"
                                        "// Option 2: Upgrade to Solidity 0.8.0+ (recommended)\n"
                                        "pragma solidity ^0.8.0;\n"
                                        "uint256 result = a + b; // Built-in overflow protection"
                                    ),
                                    swc="SWC-101",
                                    references=[
                                        "https://swcregistry.io/docs/SWC-101",
                                        "https://docs.openzeppelin.com/contracts/2.x/api/math"
                                    ]
                                ))
                                break

        return findings

    def _check_access_control(self, file_path: Path, content: str, lines: List[str]) -> List[Finding]:
        """Check for access control issues."""
        findings = []

        # Find public/external functions
        function_pattern = r'function\s+(\w+)\s*\([^)]*\)\s+(public|external)'
        
        for i, line in enumerate(lines, 1):
            match = re.search(function_pattern, line)
            if match:
                func_name = match.group(1)
                visibility = match.group(2)

                # Check for sensitive function names without modifiers
                sensitive_keywords = [
                    'withdraw', 'transfer', 'send', 'destroy', 'selfdestruct',
                    'kill', 'admin', 'owner', 'upgrade', 'pause'
                ]

                is_sensitive = any(keyword in func_name.lower() for keyword in sensitive_keywords)

                if is_sensitive:
                    # Check if function has access control modifier
                    has_modifier = bool(re.search(r'(onlyOwner|onlyAdmin|require\s*\()', line))

                    # Look ahead a few lines for require statements
                    if not has_modifier and i < len(lines):
                        next_lines = '\n'.join(lines[i:min(i+5, len(lines))])
                        has_modifier = bool(re.search(r'require\s*\(\s*msg\.sender\s*==', next_lines))

                    if not has_modifier:
                        findings.append(Finding(
                            title=f"Missing Access Control on {visibility.capitalize()} Function",
                            severity=Severity.CRITICAL,
                            vuln_type=VulnerabilityType.ACCESS_CONTROL,
                            description=(
                                f"Function '{func_name}' appears to be sensitive but lacks access control. "
                                "This could allow unauthorized users to execute critical operations."
                            ),
                            file_path=str(file_path),
                            line_number=i,
                            code_snippet=line.strip(),
                            confidence=75,
                            mitigation=(
                                "Add access control modifier or require statement:\n\n"
                                "// Option 1: Use OpenZeppelin Ownable\n"
                                "import '@openzeppelin/contracts/access/Ownable.sol';\n"
                                "contract MyContract is Ownable {\n"
                                f"    function {func_name}() {visibility} onlyOwner {{\n"
                                "        // function body\n"
                                "    }\n"
                                "}\n\n"
                                "// Option 2: Custom modifier\n"
                                "modifier onlyAdmin() {\n"
                                "    require(msg.sender == admin, 'Not authorized');\n"
                                "    _;\n"
                                "}"
                            ),
                            swc="SWC-105",
                            references=[
                                "https://swcregistry.io/docs/SWC-105",
                                "https://docs.openzeppelin.com/contracts/4.x/access-control"
                            ]
                        ))

        return findings

    def _check_timestamp_dependence(self, file_path: Path, content: str, lines: List[str]) -> List[Finding]:
        """Check for timestamp dependence vulnerabilities."""
        findings = []

        timestamp_patterns = [
            r'block\.timestamp',
            r'block\.number',
            r'now\s',
        ]

        for i, line in enumerate(lines, 1):
            for pattern in timestamp_patterns:
                if re.search(pattern, line) and not line.strip().startswith('//'):
                    # Check if it's used in critical logic
                    critical_contexts = ['require', 'if', 'assert', '==', '>', '<', '>=', '<=']
                    is_critical = any(ctx in line for ctx in critical_contexts)

                    if is_critical:
                        findings.append(Finding(
                            title="Timestamp Dependence",
                            severity=Severity.MEDIUM,
                            vuln_type=VulnerabilityType.TIMESTAMP_DEPENDENCE,
                            description=(
                                "Block timestamp is used in conditional logic. "
                                "Miners can manipulate timestamps within ~15 seconds."
                            ),
                            file_path=str(file_path),
                            line_number=i,
                            code_snippet=line.strip(),
                            confidence=85,
                            mitigation=(
                                "Avoid using block.timestamp for critical logic:\n\n"
                                "// Avoid for randomness\n"
                                "// Use Chainlink VRF instead\n\n"
                                "// If timestamp is needed:\n"
                                "// - Don't rely on exact values\n"
                                "// - Use it only for long time periods (> 15 minutes)\n"
                                "// - Consider using block.number for intervals"
                            ),
                            swc="SWC-116",
                            references=[
                                "https://swcregistry.io/docs/SWC-116",
                                "https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/timestamp-dependence/"
                            ]
                        ))
                        break

        return findings

    def _check_dangerous_operations(self, file_path: Path, content: str, lines: List[str]) -> List[Finding]:
        """Check for dangerous operations like selfdestruct and delegatecall."""
        findings = []

        # Check for selfdestruct
        for i, line in enumerate(lines, 1):
            if 'selfdestruct' in line.lower() and not line.strip().startswith('//'):
                findings.append(Finding(
                    title="Unprotected Selfdestruct",
                    severity=Severity.CRITICAL,
                    vuln_type=VulnerabilityType.SELFDESTRUCT,
                    description=(
                        "selfdestruct can permanently destroy the contract. "
                        "Ensure proper access control is implemented."
                    ),
                    file_path=str(file_path),
                    line_number=i,
                    code_snippet=line.strip(),
                    confidence=90,
                    mitigation=(
                        "Protect selfdestruct with strict access control:\n\n"
                        "function destroy() external onlyOwner {\n"
                        "    require(msg.sender == owner, 'Not authorized');\n"
                        "    // Additional safety checks\n"
                        "    selfdestruct(payable(owner));\n"
                        "}\n\n"
                        "Consider if selfdestruct is really necessary."
                    ),
                    swc="SWC-106",
                    references=[
                        "https://swcregistry.io/docs/SWC-106"
                    ]
                ))

            # Check for delegatecall
            if 'delegatecall' in line and not line.strip().startswith('//'):
                findings.append(Finding(
                    title="Dangerous Delegatecall Usage",
                    severity=Severity.HIGH,
                    vuln_type=VulnerabilityType.DANGEROUS_DELEGATECALL,
                    description=(
                        "delegatecall executes code in the context of the calling contract. "
                        "This can be exploited to modify state variables or take control."
                    ),
                    file_path=str(file_path),
                    line_number=i,
                    code_snippet=line.strip(),
                    confidence=85,
                    mitigation=(
                        "Exercise extreme caution with delegatecall:\n\n"
                        "1. Only delegatecall to trusted, audited contracts\n"
                        "2. Validate the target address is whitelisted\n"
                        "3. Understand storage layout compatibility\n"
                        "4. Consider using library calls instead\n\n"
                        "// Safe pattern\n"
                        "require(trustedContracts[target], 'Untrusted target');\n"
                        "(bool success, ) = target.delegatecall(data);"
                    ),
                    swc="SWC-112",
                    references=[
                        "https://swcregistry.io/docs/SWC-112",
                        "https://ethereum.stackexchange.com/questions/3667/difference-between-call-callcode-and-delegatecall"
                    ]
                ))

        return findings

    def _check_unchecked_calls(self, file_path: Path, content: str, lines: List[str]) -> List[Finding]:
        """Check for unchecked external calls."""
        findings = []

        unchecked_call_patterns = [
            r'\.call\{',
            r'\.send\(',
            r'\.transfer\(',
        ]

        for i, line in enumerate(lines, 1):
            for pattern in unchecked_call_patterns:
                if re.search(pattern, line) and not line.strip().startswith('//'):
                    # Check if return value is checked
                    has_check = bool(re.search(r'(bool|require|assert|if)\s*.*' + pattern, line))
                    
                    # Look at surrounding lines
                    if not has_check and i > 0:
                        context = '\n'.join(lines[max(0, i-2):min(len(lines), i+2)])
                        has_check = bool(re.search(r'(require|assert)\s*\(', context))

                    if not has_check and '.call{' in line:
                        findings.append(Finding(
                            title="Unchecked External Call",
                            severity=Severity.MEDIUM,
                            vuln_type=VulnerabilityType.UNCHECKED_CALL,
                            description=(
                                "External call return value is not checked. "
                                "Failed calls may go unnoticed."
                            ),
                            file_path=str(file_path),
                            line_number=i,
                            code_snippet=line.strip(),
                            confidence=75,
                            mitigation=(
                                "Always check return values:\n\n"
                                "// Check call success\n"
                                "(bool success, ) = recipient.call{value: amount}(\"\");\n"
                                "require(success, 'Transfer failed');\n\n"
                                "// Or use transfer() for simple ether transfers\n"
                                "payable(recipient).transfer(amount);"
                            ),
                            references=[
                                "https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/"
                            ]
                        ))

        return findings

    def _check_gas_optimization(self, file_path: Path, content: str, lines: List[str]) -> List[Finding]:
        """Check for gas optimization opportunities."""
        findings = []

        # Check for unbounded loops
        for i, line in enumerate(lines, 1):
            if re.search(r'for\s*\(', line) and not line.strip().startswith('//'):
                # Look for array.length in loop condition
                if 'length' in line or (i < len(lines) and 'length' in lines[i]):
                    findings.append(Finding(
                        title="Potential Gas Issue: Unbounded Loop",
                        severity=Severity.GAS,
                        vuln_type=VulnerabilityType.GAS_ISSUES,
                        description=(
                            "Loop iterating over array length may cause DoS if array grows large. "
                            "Gas costs can exceed block gas limit."
                        ),
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        confidence=60,
                        mitigation=(
                            "Optimize loops:\n\n"
                            "1. Cache array length:\n"
                            "uint256 length = array.length;\n"
                            "for (uint256 i = 0; i < length; i++) { ... }\n\n"
                            "2. Consider pagination for large datasets\n"
                            "3. Limit array size\n"
                            "4. Use mappings instead of arrays where possible"
                        ),
                        swc="SWC-128",
                        gas_impact="HIGH",
                        references=[
                            "https://swcregistry.io/docs/SWC-128"
                        ]
                    ))

        return findings

    def _check_best_practices(self, file_path: Path, content: str, lines: List[str]) -> List[Finding]:
        """Check for Solidity best practices."""
        findings = []

        # Check for use of assert vs require
        for i, line in enumerate(lines, 1):
            if 'assert(' in line and not line.strip().startswith('//'):
                findings.append(Finding(
                    title="Use of assert() Instead of require()",
                    severity=Severity.LOW,
                    vuln_type=VulnerabilityType.BEST_PRACTICES,
                    description=(
                        "assert() should be used for internal errors and invariants. "
                        "Use require() for validating inputs and conditions."
                    ),
                    file_path=str(file_path),
                    line_number=i,
                    code_snippet=line.strip(),
                    confidence=50,
                    mitigation=(
                        "Use require() for input validation:\n\n"
                        "// require() - for input validation (refunds remaining gas)\n"
                        "require(amount > 0, 'Amount must be positive');\n\n"
                        "// assert() - for internal errors (consumes all gas)\n"
                        "assert(balance >= amount); // Should never fail if logic is correct"
                    ),
                    references=[
                        "https://docs.soliditylang.org/en/latest/control-structures.html#error-handling-assert-require-revert-and-exceptions"
                    ]
                ))

        return findings

# === Core Scanner ===
class SmartContractScanner:
    """Main smart contract scanner class."""

    def __init__(
        self,
        scan_path: Path,
        deep_analysis: bool = False,
        pragma_check: bool = True,
        ignore_patterns: Optional[List[str]] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize scanner.

        Args:
            scan_path: Path to scan
            deep_analysis: Enable deep analysis
            pragma_check: Enable pragma version checking
            ignore_patterns: Additional ignore patterns
            logger: Logger instance
        """
        self.scan_path = scan_path
        self.deep_analysis = deep_analysis
        self.pragma_check = pragma_check
        self.logger = logger or logging.getLogger(__name__)

        self.ignore_patterns = DEFAULT_IGNORE_PATTERNS.copy()
        if ignore_patterns:
            self.ignore_patterns.extend(ignore_patterns)

        self.result = ScanResult(scan_path=str(scan_path), scan_start=datetime.now())
        self.analyzer = SolidityAnalyzer(
            deep_analysis=deep_analysis,
            pragma_check=pragma_check,
            logger=logger
        )

    def find_solidity_files(self) -> List[Path]:
        """
        Find all Solidity files to scan.

        Returns:
            List of Solidity file paths
        """
        files_to_scan = []

        if self.scan_path.is_file():
            if self.scan_path.suffix in SOLIDITY_EXTENSIONS:
                files_to_scan.append(self.scan_path)
        else:
            for ext in SOLIDITY_EXTENSIONS:
                for file_path in self.scan_path.rglob(f'*{ext}'):
                    if not should_ignore_path(file_path, self.ignore_patterns):
                        files_to_scan.append(file_path)

        return files_to_scan

    def count_contracts(self, files: List[Path]) -> int:
        """
        Count the number of contracts in files.

        Args:
            files: List of file paths

        Returns:
            Number of contracts
        """
        contract_count = 0
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    contract_count += len(re.findall(r'\bcontract\s+\w+', content))
            except Exception:
                pass
        return contract_count

    def scan(self, console: Console) -> ScanResult:
        """
        Run the security scan.

        Args:
            console: Rich console for output

        Returns:
            Scan results
        """
        console.print("[cyan]Starting smart contract security scan...[/cyan]\n")

        # Find files
        console.print("[cyan]Discovering Solidity files...[/cyan]")
        files_to_scan = self.find_solidity_files()
        self.result.files_scanned = len(files_to_scan)
        self.result.contracts_found = self.count_contracts(files_to_scan)

        console.print(f"[cyan]Found {len(files_to_scan)} Solidity files ({self.result.contracts_found} contracts)[/cyan]\n")

        if not files_to_scan:
            console.print("[yellow]No Solidity files found to scan[/yellow]")
            return self.result

        # Scan files
        console.print("[cyan]Analyzing contracts...[/cyan]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Scanning files...", total=len(files_to_scan))

            for file_path in files_to_scan:
                findings = self.analyzer.analyze_file(file_path)
                for finding in findings:
                    self.result.add_finding(finding)

                progress.advance(task)

        self.result.scan_end = datetime.now()
        return self.result

# === Reporting ===
class Reporter:
    """Handles result reporting."""

    @staticmethod
    def print_console_report(result: ScanResult, console: Console) -> None:
        """
        Print results to console.

        Args:
            result: Scan results
            console: Rich console instance
        """
        console.print()
        duration = (result.scan_end - result.scan_start).total_seconds() if result.scan_end else 0

        console.print(Panel.fit(
            f"[bold cyan]Scan Complete[/bold cyan]\n"
            f"Path: {result.scan_path}\n"
            f"Duration: {duration:.2f}s\n"
            f"Files: {result.files_scanned} | Contracts: {result.contracts_found}",
            border_style="cyan"
        ))

        # Summary
        summary = result.get_summary()
        console.print()
        console.print("[bold]Summary:[/bold]")

        summary_table = Table(show_header=True, header_style="bold magenta")
        summary_table.add_column("Severity", style="cyan", width=15)
        summary_table.add_column("Count", justify="right", style="yellow", width=8)

        severity_colors = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "green",
            "gas": "cyan"
        }

        for severity in ["critical", "high", "medium", "low", "info", "gas"]:
            count = summary.get(severity, 0)
            color = severity_colors.get(severity, "white")
            label = "GAS OPTIMIZATION" if severity == "gas" else severity.upper()
            summary_table.add_row(
                f"[{color}]{label}[/{color}]",
                f"[{color}]{count}[/{color}]"
            )

        console.print(summary_table)

        # Detailed findings
        if result.findings:
            console.print()
            console.print("[bold]Findings by File:[/bold]")
            console.print()

            # Group by file
            by_file = {}
            for finding in result.findings:
                if finding.file_path not in by_file:
                    by_file[finding.file_path] = []
                by_file[finding.file_path].append(finding)

            for file_path, findings in sorted(by_file.items()):
                console.print(f"[bold cyan]{file_path}[/bold cyan] ({len(findings)} findings)")

                for finding in sorted(findings, key=lambda x: (x.severity.value, x.line_number)):
                    severity_color = severity_colors.get(finding.severity.value.lower().replace('_', ''), "white")
                    
                    if finding.severity.value.startswith('GAS'):
                        severity_color = "cyan"

                    console.print(f"  [{severity_color}][{finding.severity.value}][/{severity_color}] Line {finding.line_number}: {finding.title}")
                    console.print(f"     Confidence: {finding.confidence}%")
                    console.print(f"     [dim]{finding.code_snippet[:80]}...[/dim]" if len(finding.code_snippet) > 80 else f"     [dim]{finding.code_snippet}[/dim]")

                    if finding.swc:
                        console.print(f"     [dim]{finding.swc}: {SWC_REGISTRY.get(finding.swc, '')}[/dim]")

                    console.print()

        else:
            console.print("\n[green]✓ No security issues detected![/green]")
            console.print("[dim]Note: This doesn't guarantee the contract is secure. Manual review is essential.[/dim]")

        # Recommendations
        console.print("\n[bold]General Recommendations:[/bold]")
        console.print("  • Conduct professional security audit before mainnet deployment")
        console.print("  • Use tools like Slither, Mythril, and Echidna for comprehensive analysis")
        console.print("  • Implement extensive test coverage (aim for >95%)")
        console.print("  • Follow Checks-Effects-Interactions pattern")
        console.print("  • Use OpenZeppelin contracts for standard functionality")
        console.print("  • Enable and test emergency pause functionality")
        console.print("  • Deploy to testnet first and monitor behavior")

    @staticmethod
    def export_json(result: ScanResult, output_path: Path) -> None:
        """Export results to JSON."""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)

    @staticmethod
    def export_html(result: ScanResult, output_path: Path) -> None:
        """Export results to HTML."""
        summary = result.get_summary()

        findings_html = ""
        for finding in result.findings:
            sev_class = finding.severity.value.lower().replace('_', '')
            findings_html += f"""
            <div class="finding {sev_class}">
                <h3>[{finding.severity.value}] {finding.title}</h3>
                <p><strong>File:</strong> {finding.file_path} (Line {finding.line_number})</p>
                <p><strong>Type:</strong> {finding.vuln_type.value}</p>
                <p><strong>Confidence:</strong> {finding.confidence}%</p>
                <p><strong>Code:</strong> <code>{finding.code_snippet}</code></p>
                <p><strong>Description:</strong> {finding.description}</p>
                {f'<p><strong>SWC:</strong> {finding.swc} - {SWC_REGISTRY.get(finding.swc, "")}</p>' if finding.swc else ''}
                {f'<p><strong>Mitigation:</strong> <pre>{finding.mitigation}</pre></p>' if finding.mitigation else ''}
            </div>
            """

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Smart Contract Security Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; }}
                .finding {{ background: white; padding: 20px; margin: 20px 0; border-radius: 10px; border-left: 4px solid #ccc; }}
                .finding.critical {{ border-left-color: #DC3545; }}
                .finding.high {{ border-left-color: #FD7E14; }}
                .finding.medium {{ border-left-color: #FFC107; }}
                .finding.low {{ border-left-color: #0dcaf0; }}
                .finding.gas {{ border-left-color: #17a2b8; }}
                code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }}
                pre {{ background: #f4f4f4; padding: 10px; border-radius: 5px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Smart Contract Security Scan Report</h1>
                <p>Generated by {TOOL_NAME} v{VERSION} by {AUTHOR}</p>
            </div>
            <h2>Scan Path: {result.scan_path}</h2>
            <p>Files Scanned: {result.files_scanned} | Contracts: {result.contracts_found}</p>
            <p>Total Findings: {summary['total']} | Critical: {summary['critical']} | High: {summary['high']} | Medium: {summary['medium']}</p>
            {findings_html}
        </body>
        </html>
        """

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

# === CLI ===
def print_banner(console: Console) -> None:
    """Print application banner."""
    try:
        import pyfiglet
        banner = pyfiglet.figlet_format("SmartScan", font="slant")
        console.print(f"[bold cyan]{banner}[/bold cyan]")
    except ImportError:
        console.print("[bold cyan]" + "=" * 60 + "[/bold cyan]")
        console.print("[bold cyan]Smart Contract Security Scanner[/bold cyan]")
        console.print("[bold cyan]" + "=" * 60 + "[/bold cyan]")

    console.print(f"[dim]Version {VERSION} | Author: {AUTHOR}[/dim]")
    console.print()

def show_examples(console: Console) -> None:
    """Display usage examples."""
    console.print("[bold cyan]Usage Examples:[/bold cyan]\n")

    examples = [
        ("Scan single contract", "python smartcontractsecscan.py MyContract.sol"),
        ("Scan entire project", "python smartcontractsecscan.py ./contracts"),
        ("Deep analysis with pragma check", "python smartcontractsecscan.py ./contracts --deep --pragma-check"),
        ("Generate JSON report", "python smartcontractsecscan.py ./contracts --output report.json"),
        ("Generate HTML report", "python smartcontractsecscan.py ./contracts --output report.html"),
        ("Scan with custom ignores", "python smartcontractsecscan.py ./src --ignore 'test' --ignore 'mock'"),
        ("Verbose logging", "python smartcontractsecscan.py ./contracts --verbose"),
    ]

    for title, command in examples:
        console.print(f"[bold]{title}:[/bold]")
        console.print(f"  [green]{command}[/green]\n")

def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} - Static analysis for Solidity smart contracts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Author: {AUTHOR}
Use --examples for detailed usage examples.
        """
    )

    parser.add_argument('path', nargs='?', help='Path to Solidity file or project directory')
    parser.add_argument('--deep', action='store_true', help='Enable deep analysis (gas optimization, best practices)')
    parser.add_argument('--pragma-check', action='store_true', default=True, help='Check Solidity version (default: enabled)')
    parser.add_argument('--no-pragma-check', action='store_false', dest='pragma_check', help='Skip pragma version checking')
    parser.add_argument('--ignore', action='append', help='Additional ignore patterns (can be used multiple times)')
    parser.add_argument('--output', help='Output file (.json or .html)')
    parser.add_argument('--verbose', action='store_true', help='Verbose logging')
    parser.add_argument('--examples', action='store_true', help='Show detailed examples')
    parser.add_argument('--version', action='version', version=f'{TOOL_NAME} v{VERSION} by {AUTHOR}')
    parser.add_argument('--no-banner', action='store_true', help='Skip banner')

    args = parser.parse_args()

    console = Console()

    if args.examples:
        if not args.no_banner:
            print_banner(console)
        show_examples(console)
        return 0

    if not args.path:
        console.print("[red]Error: Path is required[/red]")
        parser.print_help()
        return 1

    if not args.no_banner:
        print_banner(console)

    # Display security warning
    console.print(Panel(Text(SECURITY_WARNING, style="yellow"), title="[yellow]SECURITY NOTICE[/yellow]", border_style="yellow"))
    console.print()

    logger = setup_logging(args.verbose)

    scan_path = Path(args.path)
    if not scan_path.exists():
        console.print(f"[red]Error: Path does not exist: {scan_path}[/red]")
        return 1

    # Display config
    console.print("[bold]Scan Configuration:[/bold]")
    console.print(f"  Path: [cyan]{scan_path}[/cyan]")
    console.print(f"  Deep Analysis: {'[yellow]Yes[/yellow]' if args.deep else '[green]No[/green]'}")
    console.print(f"  Pragma Check: {'[yellow]Yes[/yellow]' if args.pragma_check else '[green]No[/green]'}")
    console.print()

    # Run scan
    try:
        scanner = SmartContractScanner(
            scan_path=scan_path,
            deep_analysis=args.deep,
            pragma_check=args.pragma_check,
            ignore_patterns=args.ignore,
            logger=logger
        )

        result = scanner.scan(console)

        # Display results
        Reporter.print_console_report(result, console)

        # Export if requested
        if args.output:
            output_path = Path(args.output)
            if output_path.suffix.lower() == '.json':
                Reporter.export_json(result, output_path)
                console.print(f"\n[green]✓[/green] JSON report saved to: {output_path}")
            elif output_path.suffix.lower() == '.html':
                Reporter.export_html(result, output_path)
                console.print(f"\n[green]✓[/green] HTML report saved to: {output_path}")

        summary = result.get_summary()
        if summary['critical'] > 0 or summary['high'] > 0:
            return 1
        return 0

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted[/yellow]")
        return 1
    except Exception as e:
        console.print(f"\n[red]Fatal error: {e}[/red]")
        logger.exception("Fatal error")
        return 1

if __name__ == "__main__":
    sys.exit(main())
