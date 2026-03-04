"""
Aegis AI — CVE Intelligence Database
Maps vulnerability types to real-world CVE references, CVSS scores,
impact descriptions, and mitigation guidance.

This provides context-aware intelligence that connects scanner findings
to the global vulnerability knowledge base.
"""

CVE_DATABASE = {
    "sql_injection": {
        "cve_examples": [
            {"id": "CVE-2023-34362", "product": "MOVEit Transfer", "description": "SQL injection allowing unauthenticated remote code execution"},
            {"id": "CVE-2022-22965", "product": "Spring Framework", "description": "Spring4Shell — RCE via data binding to class loader"},
            {"id": "CVE-2023-36844", "product": "Juniper Networks", "description": "PHP external variable modification leading to RCE"},
            {"id": "CVE-2021-27065", "product": "Microsoft Exchange", "description": "ProxyLogon — arbitrary file write via post-auth SSRF + SQLi"},
        ],
        "cvss_score": 9.8,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity_label": "Critical",
        "impact": "Database compromise, data exfiltration, authentication bypass, and potential remote code execution via stored procedures",
        "mitigation": "Use parameterized queries or prepared statements. Adopt ORM frameworks. Apply input validation and least-privilege database accounts.",
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    },

    "xss": {
        "cve_examples": [
            {"id": "CVE-2023-26136", "product": "tough-cookie", "description": "Prototype pollution via cookie parsing enabling XSS"},
            {"id": "CVE-2023-29489", "product": "cPanel", "description": "Reflected XSS via unvalidated input in web interface"},
            {"id": "CVE-2022-22947", "product": "Spring Cloud Gateway", "description": "Code injection via SpEL expression evaluation"},
        ],
        "cvss_score": 7.2,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "severity_label": "High",
        "impact": "Session hijacking, credential theft, malicious script execution, defacement, and keylogging",
        "mitigation": "Sanitize and encode all user inputs. Implement Content Security Policy (CSP) headers. Use framework-level auto-escaping.",
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    },

    "open_redirect": {
        "cve_examples": [
            {"id": "CVE-2021-32618", "product": "Flask-Security", "description": "Open redirect via unvalidated next parameter"},
            {"id": "CVE-2023-45133", "product": "Babel", "description": "Arbitrary code execution via crafted configuration"},
            {"id": "CVE-2022-27774", "product": "curl", "description": "Credential exposure via HTTP redirect to different protocol"},
        ],
        "cvss_score": 6.1,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "severity_label": "Medium",
        "impact": "Phishing attacks, credential harvesting, and malicious redirection to attacker-controlled sites",
        "mitigation": "Validate redirect URLs against an allowlist. Use relative URLs for internal redirects. Display confirmation page for external redirects.",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect",
            "https://cwe.mitre.org/data/definitions/601.html",
        ],
    },

    "ssti": {
        "cve_examples": [
            {"id": "CVE-2019-8341", "product": "Jinja2", "description": "Sandbox escape via string formatting in template expressions"},
            {"id": "CVE-2023-46747", "product": "F5 BIG-IP", "description": "Unauthenticated RCE via request smuggling and SSTI"},
            {"id": "CVE-2022-22954", "product": "VMware Workspace ONE", "description": "Server-side template injection leading to RCE"},
        ],
        "cvss_score": 9.0,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity_label": "Critical",
        "impact": "Remote code execution, full server compromise, data exfiltration, and lateral movement",
        "mitigation": "Never pass user-controlled data to template engines. Use sandboxed template environments. Validate and sanitize all inputs.",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
            "https://cwe.mitre.org/data/definitions/94.html",
        ],
    },

    "missing_security_header": {
        "cve_examples": [
            {"id": "CVE-2021-23383", "product": "handlebars", "description": "Prototype pollution via missing CSP allowing script injection"},
            {"id": "CVE-2022-31629", "product": "PHP", "description": "Cookie injection via missing security headers in HTTP response"},
        ],
        "cvss_score": 4.3,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "severity_label": "Medium",
        "impact": "Increased attack surface for XSS, clickjacking, MIME-sniffing, and protocol downgrade attacks",
        "mitigation": "Implement Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy headers.",
        "references": [
            "https://owasp.org/www-project-secure-headers/",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#security",
        ],
    },

    "server_version_disclosure": {
        "cve_examples": [
            {"id": "CVE-2017-15906", "product": "OpenSSH", "description": "Read-only bypass via version-specific exploit targeting disclosed version"},
        ],
        "cvss_score": 2.6,
        "cvss_vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "severity_label": "Low",
        "impact": "Aids attackers in identifying known CVEs for the specific server version, enabling targeted exploitation",
        "mitigation": "Configure the server to suppress version information in HTTP response headers.",
        "references": [
            "https://cwe.mitre.org/data/definitions/200.html",
        ],
    },

    "path_traversal": {
        "cve_examples": [
            {"id": "CVE-2023-44487", "product": "HTTP/2 implementations", "description": "Rapid reset attack enabling DoS via path manipulation"},
            {"id": "CVE-2021-41773", "product": "Apache HTTP Server", "description": "Path traversal and file disclosure via crafted URI"},
            {"id": "CVE-2024-21762", "product": "Fortinet FortiOS", "description": "Out-of-bound write via path traversal leading to RCE"},
        ],
        "cvss_score": 8.6,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity_label": "High",
        "impact": "Arbitrary file read, source code disclosure, configuration file leakage, and potential remote code execution",
        "mitigation": "Validate and canonicalize file paths. Use allowlists for accessible resources. Implement chroot or containerization.",
        "references": [
            "https://owasp.org/www-community/attacks/Path_Traversal",
            "https://cwe.mitre.org/data/definitions/22.html",
        ],
    },

    "file_upload_bypass": {
        "cve_examples": [
            {"id": "CVE-2023-33246", "product": "Apache RocketMQ", "description": "RCE via unrestricted file upload and deserialization"},
            {"id": "CVE-2023-50164", "product": "Apache Struts", "description": "Path traversal in file upload enabling RCE"},
        ],
        "cvss_score": 9.8,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity_label": "Critical",
        "impact": "Remote code execution via uploaded webshell, full server compromise, and data exfiltration",
        "mitigation": "Validate file types with allowlists. Store uploads outside the web root. Scan files with antivirus. Rename uploaded files.",
        "references": [
            "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
            "https://cwe.mitre.org/data/definitions/434.html",
        ],
    },

    "idor": {
        "cve_examples": [
            {"id": "CVE-2023-27350", "product": "PaperCut NG/MF", "description": "Authentication bypass via insecure direct object reference"},
            {"id": "CVE-2022-44877", "product": "CentOS Control Web Panel", "description": "IDOR leading to unauthenticated RCE"},
        ],
        "cvss_score": 7.5,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "severity_label": "High",
        "impact": "Unauthorized access to other users' data, privilege escalation, and information disclosure",
        "mitigation": "Implement proper authorization checks. Use indirect references (UUIDs). Enforce access control on every request.",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
            "https://cwe.mitre.org/data/definitions/284.html",
        ],
    },

    "auth_bypass": {
        "cve_examples": [
            {"id": "CVE-2023-22515", "product": "Atlassian Confluence", "description": "Broken access control allowing admin account creation"},
            {"id": "CVE-2023-46805", "product": "Ivanti Connect Secure", "description": "Authentication bypass via path traversal"},
            {"id": "CVE-2024-1709", "product": "ConnectWise ScreenConnect", "description": "Authentication bypass via setup wizard re-access"},
        ],
        "cvss_score": 9.8,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity_label": "Critical",
        "impact": "Full administrative access, complete application compromise, data theft, and lateral movement",
        "mitigation": "Implement robust authentication mechanisms. Use multi-factor authentication. Apply defense-in-depth access controls.",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/",
            "https://cwe.mitre.org/data/definitions/287.html",
        ],
    },
}
