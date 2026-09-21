"""Security Rules Definition and Regex Signature Catalog.

Strictly deterministic rule patterns for detecting malicious attack vectors
including Path Traversal, Command Injection, SQL Injection, XSS, XXE,
Null Byte Injection, and Header Injections.
"""
from dataclasses import dataclass
from enum import Enum
import re
from typing import List, Optional, Tuple


class RuleCategory(str, Enum):
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    SQL_INJECTION = "SQL_INJECTION"
    CROSS_SITE_SCRIPTING = "CROSS_SITE_SCRIPTING"
    XML_EXTERNAL_ENTITY = "XML_EXTERNAL_ENTITY"
    NULL_BYTE_INJECTION = "NULL_BYTE_INJECTION"
    HEADER_INJECTION = "HEADER_INJECTION"
    EVASION_TECHNIQUE = "EVASION_TECHNIQUE"


class RuleSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class SecurityRule:
    rule_id: str
    name: str
    category: RuleCategory
    severity: RuleSeverity
    description: str
    pattern: re.Pattern

    def matches(self, text: str) -> Optional[re.Match]:
        """Test if the rule regex matches the provided text."""
        return self.pattern.search(text)


# ============================================================================
# 1. Path Traversal & Sensitive File Rules
# ============================================================================
PATH_TRAVERSAL_RULES: List[SecurityRule] = [
    SecurityRule(
        rule_id="PT-001",
        name="Dot-Dot-Slash Traversal",
        category=RuleCategory.PATH_TRAVERSAL,
        severity=RuleSeverity.CRITICAL,
        description="Detects standard directory traversal patterns (e.g., ../ or ..\\)",
        pattern=re.compile(r"(?:\.\.[\\/]+|\.[\\/]\.\.[\\/])", re.IGNORECASE),
    ),
    SecurityRule(
        rule_id="PT-002",
        name="URL-Encoded Traversal",
        category=RuleCategory.PATH_TRAVERSAL,
        severity=RuleSeverity.CRITICAL,
        description="Detects single URL-encoded path traversal sequences (e.g. %2e%2e%2f, %2e%2e/, ..%2f)",
        pattern=re.compile(
            r"(?:%(?:2e|2E){2}(?:%(?:2f|2F|5c|5C)|[\\/])|\.\.(?:%(?:2f|2F|5c|5C))|(?:%(?:2e|2E))\.(?:%(?:2f|2F|5c|5C)|[\\/]))",
            re.IGNORECASE,
        ),
    ),
    SecurityRule(
        rule_id="PT-003",
        name="Double-Encoded Traversal",
        category=RuleCategory.PATH_TRAVERSAL,
        severity=RuleSeverity.CRITICAL,
        description="Detects nested or double URL-encoded traversal (e.g., %252e%252e%252f)",
        pattern=re.compile(
            r"(?:%25(?:2e|2E){2}%25(?:2f|2F|5c|5C)|%252e%252e[\\/])",
            re.IGNORECASE,
        ),
    ),
    SecurityRule(
        rule_id="PT-004",
        name="Unix Sensitive File Access",
        category=RuleCategory.PATH_TRAVERSAL,
        severity=RuleSeverity.CRITICAL,
        description="Detects requests targeting critical Unix files and directories",
        pattern=re.compile(
            r"(?:/etc/(?:passwd|shadow|group|hosts|sudoers|issue)|/proc/(?:self|version|cpuinfo|net)|\b(?:etc/passwd|etc/shadow)\b)",
            re.IGNORECASE,
        ),
    ),
    SecurityRule(
        rule_id="PT-005",
        name="Windows Sensitive File Access",
        category=RuleCategory.PATH_TRAVERSAL,
        severity=RuleSeverity.CRITICAL,
        description="Detects requests targeting sensitive Windows directories or files",
        pattern=re.compile(
            r"(?:windows[\\/]system32|winnt[\\/]system32|system32[\\/]drivers[\\/]etc[\\/]hosts|boot\.ini|win\.ini|cmd\.exe|powershell\.exe)",
            re.IGNORECASE,
        ),
    ),
    SecurityRule(
        rule_id="PT-006",
        name="Sensitive Config/Secret Access",
        category=RuleCategory.PATH_TRAVERSAL,
        severity=RuleSeverity.HIGH,
        description="Detects access to sensitive configuration files, VCS metadata, or keys",
        pattern=re.compile(
            r"(?:\.env(?:\.local|\.prod|\.dev|\.stage)?$|\.git(?:[\\/]|$)|\.aws[\\/](?:credentials|config)|\.ssh[\\/](?:id_rsa|authorized_keys|known_hosts)|web\.config)",
            re.IGNORECASE,
        ),
    ),
]

# ============================================================================
# 2. Null Byte Injection Rules
# ============================================================================
NULL_BYTE_RULES: List[SecurityRule] = [
    SecurityRule(
        rule_id="NB-001",
        name="Null Byte Injection",
        category=RuleCategory.NULL_BYTE_INJECTION,
        severity=RuleSeverity.CRITICAL,
        description="Detects null byte poisoning used for file extension truncation or bypass",
        pattern=re.compile(r"(?:%00|\\x00|\\u0000|\x00)", re.IGNORECASE),
    ),
]

# ============================================================================
# 3. Command Injection Rules
# ============================================================================
COMMAND_INJECTION_RULES: List[SecurityRule] = [
    SecurityRule(
        rule_id="CI-001",
        name="OS Command Chaining & Execution",
        category=RuleCategory.COMMAND_INJECTION,
        severity=RuleSeverity.CRITICAL,
        description="Detects command chaining operators followed by critical shell utilities",
        pattern=re.compile(
            r"(?:[;&|`]\s*(?:cat|ls|whoami|id|uname|netstat|curl|wget|bash|sh|zsh|powershell|cmd\.exe|nc|ncat)\b)",
            re.IGNORECASE,
        ),
    ),
    SecurityRule(
        rule_id="CI-002",
        name="Subshell Command Substitution",
        category=RuleCategory.COMMAND_INJECTION,
        severity=RuleSeverity.CRITICAL,
        description="Detects subshell execution syntax $(command) or `command`",
        pattern=re.compile(
            r"(?:\$\((?:cat|ls|whoami|id|uname|hostname|curl|wget)\b|`(?:cat|ls|whoami|id|uname|hostname|curl|wget)\b.*`)",
            re.IGNORECASE,
        ),
    ),
]

# ============================================================================
# 4. SQL Injection Rules
# ============================================================================
SQLI_RULES: List[SecurityRule] = [
    SecurityRule(
        rule_id="SQL-001",
        name="Union Based SQL Injection",
        category=RuleCategory.SQL_INJECTION,
        severity=RuleSeverity.CRITICAL,
        description="Detects UNION SELECT SQL injection vectors",
        pattern=re.compile(r"\bUNION(?:\s+ALL)?\s+SELECT\b", re.IGNORECASE),
    ),
    SecurityRule(
        rule_id="SQL-002",
        name="Boolean / Tautology SQL Injection",
        category=RuleCategory.SQL_INJECTION,
        severity=RuleSeverity.HIGH,
        description="Detects classic tautology based SQL injection expressions",
        pattern=re.compile(
            r"(?:(?:'|\")\s*(?:OR|AND)\s*[\d\w]+\s*=\s*[\d\w]+|(?:\bOR\b|\bAND\b)\s+1\s*=\s*1\b)",
            re.IGNORECASE,
        ),
    ),
    SecurityRule(
        rule_id="SQL-003",
        name="Time/Stacked SQL Injection",
        category=RuleCategory.SQL_INJECTION,
        severity=RuleSeverity.CRITICAL,
        description="Detects sleep/benchmark calls or stacked destructive commands",
        pattern=re.compile(
            r"(?:\bWAITFOR\s+DELAY\b|\bSLEEP\s*\(\s*\d+\s*\)|\bBENCHMARK\s*\(\s*\d+|\bDROP\s+TABLE\b|\bEXEC\s*\(\s*xp_cmdshell\b)",
            re.IGNORECASE,
        ),
    ),
]

# ============================================================================
# 5. Cross-Site Scripting (XSS) Rules
# ============================================================================
XSS_RULES: List[SecurityRule] = [
    SecurityRule(
        rule_id="XSS-001",
        name="HTML Script Tag Injection",
        category=RuleCategory.CROSS_SITE_SCRIPTING,
        severity=RuleSeverity.HIGH,
        description="Detects direct script tags in payloads",
        pattern=re.compile(r"<\s*script[^>]*>.*?(?:<\s*/\s*script\s*>|$)", re.IGNORECASE | re.DOTALL),
    ),
    SecurityRule(
        rule_id="XSS-002",
        name="JavaScript URI Scheme / Event Handler",
        category=RuleCategory.CROSS_SITE_SCRIPTING,
        severity=RuleSeverity.HIGH,
        description="Detects javascript: pseudo-protocol or inline event handlers",
        pattern=re.compile(
            r"(?:javascript\s*:[^\"'>]+|\bon(?:error|load|click|mouseover|focus|blur)\s*=)",
            re.IGNORECASE,
        ),
    ),
    SecurityRule(
        rule_id="XSS-003",
        name="Dangerous HTML Elements (Iframe/Object/Embed)",
        category=RuleCategory.CROSS_SITE_SCRIPTING,
        severity=RuleSeverity.HIGH,
        description="Detects injection of embedding frames or objects",
        pattern=re.compile(r"<\s*(?:iframe|object|embed|svg|img)[^>]+(?:src|href|onload|onerror)\s*=", re.IGNORECASE),
    ),
]

# ============================================================================
# 6. XML External Entity (XXE) Rules
# ============================================================================
XXE_RULES: List[SecurityRule] = [
    SecurityRule(
        rule_id="XXE-001",
        name="XML External Entity Declaration",
        category=RuleCategory.XML_EXTERNAL_ENTITY,
        severity=RuleSeverity.CRITICAL,
        description="Detects DOCTYPE ENTITY definitions with SYSTEM or PUBLIC external references",
        pattern=re.compile(
            r"(?:<!ENTITY\s+[^>]+SYSTEM\s+[\"'](?:file|http|https|ftp|gopher|expect|data):|<!DOCTYPE\s+[^>]+SYSTEM\s+[\"'])",
            re.IGNORECASE,
        ),
    ),
    SecurityRule(
        rule_id="XXE-002",
        name="XML Parameter Entity",
        category=RuleCategory.XML_EXTERNAL_ENTITY,
        severity=RuleSeverity.HIGH,
        description="Detects XML parameter entity expansion techniques",
        pattern=re.compile(r"<!ENTITY\s+%\s+[^>]+>", re.IGNORECASE),
    ),
]

# ============================================================================
# 7. Header Injection Rules
# ============================================================================
HEADER_INJECTION_RULES: List[SecurityRule] = [
    SecurityRule(
        rule_id="HI-001",
        name="CRLF / Header Splitting",
        category=RuleCategory.HEADER_INJECTION,
        severity=RuleSeverity.CRITICAL,
        description="Detects Carriage Return / Line Feed characters within header values",
        pattern=re.compile(r"[\r\n]", re.IGNORECASE),
    ),
]

# Aggregate registry for body and general payload inspection (excludes header-only CRLF injection)
PAYLOAD_RULES_REGISTRY: List[SecurityRule] = (
    PATH_TRAVERSAL_RULES
    + NULL_BYTE_RULES
    + COMMAND_INJECTION_RULES
    + SQLI_RULES
    + XSS_RULES
    + XXE_RULES
)

# Aggregate full registry
RULES_REGISTRY: List[SecurityRule] = (
    PAYLOAD_RULES_REGISTRY
    + HEADER_INJECTION_RULES
)


def match_payload_rules(text: str) -> Optional[Tuple[SecurityRule, re.Match]]:
    """Check text against general payload rules (excluding header-specific CRLF rules)."""
    if not text:
        return None
    for rule in PAYLOAD_RULES_REGISTRY:
        match = rule.matches(text)
        if match:
            return rule, match
    return None


def match_all_rules(text: str) -> Optional[Tuple[SecurityRule, re.Match]]:
    """Check text against all rules in the registry.

    Returns the first matching rule and match object if triggered, else None.
    """
    if not text:
        return None
    for rule in RULES_REGISTRY:
        match = rule.matches(text)
        if match:
            return rule, match
    return None


def match_category_rules(
    text: str, category: RuleCategory
) -> Optional[Tuple[SecurityRule, re.Match]]:
    """Check text against rules of a specific category."""
    if not text:
        return None
    for rule in RULES_REGISTRY:
        if rule.category == category:
            match = rule.matches(text)
            if match:
                return rule, match
    return None
