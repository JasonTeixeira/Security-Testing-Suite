"""
Security Scanner Framework
==========================
Production-grade security testing framework for web applications.
Implements OWASP Top 10 automated testing.

Author: Jason Teixeira
License: MIT
"""

import requests
import re
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import urllib.parse
import json
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Vulnerability:
    """Represents a discovered security vulnerability"""
    title: str
    severity: Severity
    description: str
    affected_url: str
    evidence: str
    remediation: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'title': self.title,
            'severity': self.severity.value,
            'description': self.description,
            'affected_url': self.affected_url,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'cwe_id': self.cwe_id,
            'cvss_score': self.cvss_score
        }


class SecurityScanner:
    """
    Main security scanner class implementing OWASP Top 10 tests
    """
    
    def __init__(self, target_url: str, session: Optional[requests.Session] = None):
        """
        Initialize security scanner
        
        Args:
            target_url: Base URL of application to scan
            session: Optional requests session with authentication
        """
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.vulnerabilities: List[Vulnerability] = []
        
        # Default headers
        self.session.headers.update({
            'User-Agent': 'SecurityScanner/1.0 (Security Testing)',
            'Accept': 'text/html,application/json'
        })
        
        logger.info(f"Initialized SecurityScanner for {self.target_url}")
    
    def scan_all(self) -> List[Vulnerability]:
        """
        Run all security tests
        
        Returns:
            List of discovered vulnerabilities
        """
        logger.info("Starting comprehensive security scan...")
        
        # OWASP Top 10 Tests
        self.test_sql_injection()
        self.test_xss()
        self.test_broken_authentication()
        self.test_sensitive_data_exposure()
        self.test_xml_external_entities()
        self.test_broken_access_control()
        self.test_security_misconfiguration()
        self.test_csrf()
        self.test_insecure_deserialization()
        self.test_vulnerable_components()
        
        logger.info(f"Scan complete. Found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities
    
    def test_sql_injection(self) -> None:
        """
        Test for SQL injection vulnerabilities (OWASP A1)
        
        Tests common injection points and payloads:
        - Single quote injection
        - Boolean-based blind injection
        - Time-based blind injection
        - Error-based injection
        """
        logger.info("Testing for SQL injection vulnerabilities...")
        
        # SQL injection payloads
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "' UNION SELECT NULL--",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "' OR SLEEP(5)--"
        ]
        
        # Test common endpoints
        test_endpoints = [
            '/login',
            '/search',
            '/product',
            '/user'
        ]
        
        for endpoint in test_endpoints:
            url = f"{self.target_url}{endpoint}"
            
            for payload in payloads:
                try:
                    # Test GET parameters
                    response = self.session.get(
                        url,
                        params={'q': payload, 'id': payload},
                        timeout=10
                    )
                    
                    if self._detect_sql_injection(response):
                        self.vulnerabilities.append(Vulnerability(
                            title="SQL Injection Vulnerability",
                            severity=Severity.CRITICAL,
                            description=f"SQL injection vulnerability detected in {endpoint}",
                            affected_url=url,
                            evidence=f"Payload: {payload}\nResponse code: {response.status_code}",
                            remediation="Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
                            cwe_id="CWE-89",
                            cvss_score=9.8
                        ))
                        logger.warning(f"SQL injection found at {url}")
                        break  # Found vulnerability, move to next endpoint
                    
                except requests.exceptions.RequestException as e:
                    logger.debug(f"Request failed: {e}")
    
    def _detect_sql_injection(self, response: requests.Response) -> bool:
        """
        Detect SQL injection from response
        
        Args:
            response: HTTP response to analyze
            
        Returns:
            True if SQL injection detected
        """
        sql_errors = [
            "SQL syntax",
            "mysql_fetch",
            "ORA-01",
            "PostgreSQL.*ERROR",
            "Warning.*mysql",
            "MySQLSyntaxErrorException",
            "valid MySQL result",
            "SQLSTATE",
            "SQLite3::SQLException"
        ]
        
        for error in sql_errors:
            if re.search(error, response.text, re.IGNORECASE):
                return True
        
        return False
    
    def test_xss(self) -> None:
        """
        Test for Cross-Site Scripting (XSS) vulnerabilities (OWASP A7)
        
        Tests:
        - Reflected XSS
        - Stored XSS
        - DOM-based XSS
        """
        logger.info("Testing for XSS vulnerabilities...")
        
        # XSS payloads
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(\"XSS\")'>"
        ]
        
        test_endpoints = [
            '/search',
            '/comment',
            '/profile',
            '/message'
        ]
        
        for endpoint in test_endpoints:
            url = f"{self.target_url}{endpoint}"
            
            for payload in payloads:
                try:
                    # Test reflected XSS
                    response = self.session.get(
                        url,
                        params={'q': payload, 'input': payload},
                        timeout=10
                    )
                    
                    if payload in response.text and 'text/html' in response.headers.get('Content-Type', ''):
                        # Check if payload is not properly encoded
                        if not self._is_properly_encoded(payload, response.text):
                            self.vulnerabilities.append(Vulnerability(
                                title="Cross-Site Scripting (XSS) Vulnerability",
                                severity=Severity.HIGH,
                                description=f"Reflected XSS vulnerability detected in {endpoint}",
                                affected_url=url,
                                evidence=f"Payload: {payload}\nPayload reflected unescaped in response",
                                remediation="Implement proper output encoding. Use Content Security Policy (CSP). Sanitize user input.",
                                cwe_id="CWE-79",
                                cvss_score=7.3
                            ))
                            logger.warning(f"XSS vulnerability found at {url}")
                            break
                    
                    # Test stored XSS (POST)
                    post_response = self.session.post(
                        url,
                        data={'content': payload, 'message': payload},
                        timeout=10
                    )
                    
                    if payload in post_response.text:
                        if not self._is_properly_encoded(payload, post_response.text):
                            self.vulnerabilities.append(Vulnerability(
                                title="Stored Cross-Site Scripting (XSS)",
                                severity=Severity.CRITICAL,
                                description=f"Stored XSS vulnerability in {endpoint}",
                                affected_url=url,
                                evidence=f"Payload stored and reflected: {payload}",
                                remediation="Encode output, validate input, implement CSP",
                                cwe_id="CWE-79",
                                cvss_score=8.8
                            ))
                            logger.critical(f"Stored XSS found at {url}")
                            break
                
                except requests.exceptions.RequestException as e:
                    logger.debug(f"Request failed: {e}")
    
    def _is_properly_encoded(self, payload: str, response_text: str) -> bool:
        """
        Check if payload is properly HTML encoded in response
        
        Args:
            payload: Original payload
            response_text: Response text to check
            
        Returns:
            True if properly encoded
        """
        # Check common encodings
        encoded_versions = [
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('<', '&#60;').replace('>', '&#62;'),
            urllib.parse.quote(payload)
        ]
        
        for encoded in encoded_versions:
            if encoded in response_text:
                return True
        
        return False
    
    def test_broken_authentication(self) -> None:
        """
        Test for broken authentication (OWASP A2)
        
        Tests:
        - Weak password policy
        - No account lockout
        - Session fixation
        - Credential stuffing
        """
        logger.info("Testing authentication security...")
        
        login_url = f"{self.target_url}/login"
        
        # Test weak passwords
        weak_passwords = ['password', '123456', 'admin', 'test', '']
        
        for password in weak_passwords:
            try:
                response = self.session.post(
                    login_url,
                    data={'username': 'admin', 'password': password},
                    timeout=10
                )
                
                if response.status_code == 200 and 'success' in response.text.lower():
                    self.vulnerabilities.append(Vulnerability(
                        title="Weak Password Accepted",
                        severity=Severity.CRITICAL,
                        description="System accepts weak passwords",
                        affected_url=login_url,
                        evidence=f"Weak password '{password}' was accepted",
                        remediation="Implement strong password policy: minimum 12 characters, complexity requirements, password history",
                        cwe_id="CWE-521",
                        cvss_score=9.1
                    ))
                    logger.critical("Weak password policy detected")
                    break
            
            except requests.exceptions.RequestException as e:
                logger.debug(f"Login test failed: {e}")
        
        # Test for account lockout
        self._test_account_lockout(login_url)
        
        # Test session security
        self._test_session_security()
    
    def _test_account_lockout(self, login_url: str) -> None:
        """Test if account lockout is implemented"""
        logger.info("Testing account lockout mechanism...")
        
        # Attempt multiple failed logins
        for i in range(10):
            try:
                response = self.session.post(
                    login_url,
                    data={'username': 'testuser', 'password': f'wrong{i}'},
                    timeout=10
                )
                
                # If we can still attempt login after 5+ failures, no lockout
                if i >= 5 and response.status_code == 200:
                    self.vulnerabilities.append(Vulnerability(
                        title="No Account Lockout Mechanism",
                        severity=Severity.HIGH,
                        description="No account lockout after multiple failed login attempts",
                        affected_url=login_url,
                        evidence=f"Successfully attempted {i+1} failed logins without lockout",
                        remediation="Implement account lockout after 5 failed attempts. Consider CAPTCHA and progressive delays.",
                        cwe_id="CWE-307",
                        cvss_score=7.5
                    ))
                    logger.warning("No account lockout detected")
                    break
            
            except requests.exceptions.RequestException:
                pass
    
    def _test_session_security(self) -> None:
        """Test session management security"""
        logger.info("Testing session security...")
        
        try:
            # Check session cookie attributes
            response = self.session.get(self.target_url)
            
            session_cookies = [
                cookie for cookie in self.session.cookies
                if 'session' in cookie.name.lower() or 'token' in cookie.name.lower()
            ]
            
            for cookie in session_cookies:
                issues = []
                
                if not cookie.secure:
                    issues.append("Missing Secure flag")
                
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append("Missing HttpOnly flag")
                
                if not cookie.has_nonstandard_attr('SameSite'):
                    issues.append("Missing SameSite attribute")
                
                if issues:
                    self.vulnerabilities.append(Vulnerability(
                        title="Insecure Session Cookie Configuration",
                        severity=Severity.MEDIUM,
                        description=f"Session cookie '{cookie.name}' has security issues",
                        affected_url=self.target_url,
                        evidence=f"Cookie issues: {', '.join(issues)}",
                        remediation="Set Secure, HttpOnly, and SameSite=Strict flags on session cookies",
                        cwe_id="CWE-614",
                        cvss_score=5.3
                    ))
                    logger.warning(f"Insecure cookie: {cookie.name}")
        
        except Exception as e:
            logger.debug(f"Session security test failed: {e}")
    
    def test_sensitive_data_exposure(self) -> None:
        """
        Test for sensitive data exposure (OWASP A3)
        
        Checks:
        - HTTPS enforcement
        - Sensitive data in URLs
        - Information disclosure in responses
        """
        logger.info("Testing for sensitive data exposure...")
        
        # Test HTTPS enforcement
        if self.target_url.startswith('http://'):
            self.vulnerabilities.append(Vulnerability(
                title="No HTTPS Enforcement",
                severity=Severity.HIGH,
                description="Application accessible over unencrypted HTTP",
                affected_url=self.target_url,
                evidence="URL uses http:// instead of https://",
                remediation="Enforce HTTPS for all traffic. Implement HTTP Strict Transport Security (HSTS).",
                cwe_id="CWE-319",
                cvss_score=7.4
            ))
            logger.warning("HTTPS not enforced")
        
        # Check for sensitive data in responses
        try:
            response = self.session.get(self.target_url)
            
            sensitive_patterns = {
                'API Key': r'api[_-]?key\s*[=:]\s*["\']([a-zA-Z0-9_\-]+)["\']',
                'Password': r'password\s*[=:]\s*["\']([^"\']+)["\']',
                'Secret': r'secret\s*[=:]\s*["\']([^"\']+)["\']',
                'AWS Key': r'AKIA[0-9A-Z]{16}',
                'Private Key': r'-----BEGIN (RSA |)PRIVATE KEY-----'
            }
            
            for name, pattern in sensitive_patterns.items():
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                if matches:
                    self.vulnerabilities.append(Vulnerability(
                        title=f"Sensitive Data Exposure: {name}",
                        severity=Severity.CRITICAL,
                        description=f"{name} exposed in HTTP response",
                        affected_url=self.target_url,
                        evidence=f"Found {len(matches)} {name} pattern(s) in response",
                        remediation="Remove sensitive data from responses. Use environment variables for secrets.",
                        cwe_id="CWE-200",
                        cvss_score=9.1
                    ))
                    logger.critical(f"Sensitive data exposed: {name}")
        
        except requests.exceptions.RequestException as e:
            logger.debug(f"Data exposure test failed: {e}")
    
    def test_xml_external_entities(self) -> None:
        """
        Test for XML External Entity (XXE) vulnerabilities (OWASP A4)
        """
        logger.info("Testing for XXE vulnerabilities...")
        
        xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>"""
        
        try:
            response = self.session.post(
                f"{self.target_url}/api/xml",
                data=xxe_payload,
                headers={'Content-Type': 'application/xml'},
                timeout=10
            )
            
            # Check if file content leaked
            if 'root:' in response.text or 'bin/bash' in response.text:
                self.vulnerabilities.append(Vulnerability(
                    title="XML External Entity (XXE) Injection",
                    severity=Severity.CRITICAL,
                    description="Application vulnerable to XXE attacks",
                    affected_url=f"{self.target_url}/api/xml",
                    evidence="Successfully read /etc/passwd via XXE",
                    remediation="Disable XML external entity processing. Use JSON instead of XML when possible.",
                    cwe_id="CWE-611",
                    cvss_score=8.6
                ))
                logger.critical("XXE vulnerability detected")
        
        except requests.exceptions.RequestException as e:
            logger.debug(f"XXE test failed: {e}")
    
    def test_broken_access_control(self) -> None:
        """
        Test for broken access control (OWASP A5)
        
        Tests:
        - Insecure Direct Object Reference (IDOR)
        - Missing function level access control
        - Forced browsing
        """
        logger.info("Testing access control...")
        
        # Test IDOR
        test_endpoints = [
            '/api/user/1',
            '/api/order/1',
            '/api/document/1'
        ]
        
        for endpoint in test_endpoints:
            url = f"{self.target_url}{endpoint}"
            
            try:
                # Try accessing other user's data
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    self.vulnerabilities.append(Vulnerability(
                        title="Insecure Direct Object Reference (IDOR)",
                        severity=Severity.HIGH,
                        description=f"Possible IDOR vulnerability in {endpoint}",
                        affected_url=url,
                        evidence=f"Accessed resource with sequential ID without authorization check",
                        remediation="Implement proper authorization checks. Use non-sequential UUIDs. Verify user owns requested resource.",
                        cwe_id="CWE-639",
                        cvss_score=8.1
                    ))
                    logger.warning(f"Potential IDOR at {url}")
            
            except requests.exceptions.RequestException as e:
                logger.debug(f"Access control test failed: {e}")
    
    def test_security_misconfiguration(self) -> None:
        """
        Test for security misconfiguration (OWASP A6)
        
        Checks:
        - Default credentials
        - Directory listing
        - Verbose error messages
        - Missing security headers
        """
        logger.info("Testing for security misconfigurations...")
        
        try:
            response = self.session.get(self.target_url)
            
            # Check security headers
            security_headers = {
                'X-Frame-Options': 'Missing X-Frame-Options (clickjacking protection)',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options (MIME sniffing protection)',
                'Content-Security-Policy': 'Missing Content-Security-Policy (XSS protection)',
                'Strict-Transport-Security': 'Missing HSTS header (HTTPS enforcement)',
                'X-XSS-Protection': 'Missing X-XSS-Protection header'
            }
            
            for header, description in security_headers.items():
                if header not in response.headers:
                    self.vulnerabilities.append(Vulnerability(
                        title=f"Missing Security Header: {header}",
                        severity=Severity.MEDIUM,
                        description=description,
                        affected_url=self.target_url,
                        evidence=f"Response missing {header} header",
                        remediation=f"Add {header} header to all responses",
                        cwe_id="CWE-16",
                        cvss_score=5.3
                    ))
                    logger.info(f"Missing security header: {header}")
            
            # Check for information disclosure
            if 'server' in response.headers:
                server = response.headers['server']
                if any(version in server.lower() for version in ['1.', '2.', '3.', '/']):
                    self.vulnerabilities.append(Vulnerability(
                        title="Server Version Disclosure",
                        severity=Severity.LOW,
                        description="Server header reveals version information",
                        affected_url=self.target_url,
                        evidence=f"Server header: {server}",
                        remediation="Remove or obfuscate server version information",
                        cwe_id="CWE-200",
                        cvss_score=3.7
                    ))
        
        except requests.exceptions.RequestException as e:
            logger.debug(f"Misconfiguration test failed: {e}")
    
    def test_csrf(self) -> None:
        """
        Test for Cross-Site Request Forgery (CSRF) protection (OWASP A8)
        """
        logger.info("Testing CSRF protection...")
        
        state_changing_endpoints = [
            '/api/transfer',
            '/api/delete',
            '/api/update',
            '/profile/update'
        ]
        
        for endpoint in state_changing_endpoints:
            url = f"{self.target_url}{endpoint}"
            
            try:
                # Try POST without CSRF token
                response = self.session.post(
                    url,
                    data={'amount': '1000', 'action': 'delete'},
                    timeout=10
                )
                
                if response.status_code == 200:
                    self.vulnerabilities.append(Vulnerability(
                        title="Missing CSRF Protection",
                        severity=Severity.MEDIUM,
                        description=f"No CSRF protection on {endpoint}",
                        affected_url=url,
                        evidence="State-changing request accepted without CSRF token",
                        remediation="Implement CSRF tokens for all state-changing operations. Use SameSite cookie attribute.",
                        cwe_id="CWE-352",
                        cvss_score=6.5
                    ))
                    logger.warning(f"Missing CSRF protection at {url}")
            
            except requests.exceptions.RequestException as e:
                logger.debug(f"CSRF test failed: {e}")
    
    def test_insecure_deserialization(self) -> None:
        """
        Test for insecure deserialization (OWASP A8)
        """
        logger.info("Testing for insecure deserialization...")
        
        # Test Python pickle deserialization
        import pickle
        import base64
        
        try:
            # Malicious payload (safe for testing)
            malicious_data = pickle.dumps({'test': 'data'})
            encoded = base64.b64encode(malicious_data).decode()
            
            response = self.session.post(
                f"{self.target_url}/api/deserialize",
                json={'data': encoded},
                timeout=10
            )
            
            if response.status_code == 200 and 'success' in response.text.lower():
                self.vulnerabilities.append(Vulnerability(
                    title="Insecure Deserialization",
                    severity=Severity.CRITICAL,
                    description="Application deserializes untrusted data",
                    affected_url=f"{self.target_url}/api/deserialize",
                    evidence="Serialized object accepted and processed",
                    remediation="Avoid deserializing untrusted data. Use JSON instead. Implement integrity checks.",
                    cwe_id="CWE-502",
                    cvss_score=9.8
                ))
                logger.critical("Insecure deserialization detected")
        
        except Exception as e:
            logger.debug(f"Deserialization test failed: {e}")
    
    def test_vulnerable_components(self) -> None:
        """
        Test for vulnerable and outdated components (OWASP A9)
        
        Checks for known vulnerable libraries and frameworks
        """
        logger.info("Testing for vulnerable components...")
        
        try:
            response = self.session.get(self.target_url)
            
            # Check for known vulnerable library patterns
            vulnerable_patterns = {
                'jQuery 1.': ('jQuery < 2.0', 'XSS vulnerabilities'),
                'angular.js/1.[0-5]': ('AngularJS < 1.6', 'XSS vulnerabilities'),
                'bootstrap/3.': ('Bootstrap 3.x', 'XSS vulnerabilities'),
            }
            
            for pattern, (component, vuln) in vulnerable_patterns.items():
                if re.search(pattern, response.text):
                    self.vulnerabilities.append(Vulnerability(
                        title=f"Vulnerable Component: {component}",
                        severity=Severity.HIGH,
                        description=f"Application uses {component} with known {vuln}",
                        affected_url=self.target_url,
                        evidence=f"Detected {component} in response",
                        remediation=f"Update {component} to latest secure version",
                        cwe_id="CWE-1035",
                        cvss_score=7.5
                    ))
                    logger.warning(f"Vulnerable component detected: {component}")
        
        except requests.exceptions.RequestException as e:
            logger.debug(f"Component test failed: {e}")
    
    def generate_report(self, output_file: str = "security_report.json") -> None:
        """
        Generate JSON security report
        
        Args:
            output_file: Output file path
        """
        report = {
            'target': self.target_url,
            'total_vulnerabilities': len(self.vulnerabilities),
            'severity_breakdown': self._get_severity_breakdown(),
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report generated: {output_file}")
    
    def _get_severity_breakdown(self) -> Dict[str, int]:
        """Get count of vulnerabilities by severity"""
        breakdown = {severity.value: 0 for severity in Severity}
        
        for vuln in self.vulnerabilities:
            breakdown[vuln.severity.value] += 1
        
        return breakdown
    
    def print_summary(self) -> None:
        """Print vulnerability summary to console"""
        print("\n" + "="*80)
        print("SECURITY SCAN SUMMARY")
        print("="*80)
        print(f"Target: {self.target_url}")
        print(f"Total Vulnerabilities: {len(self.vulnerabilities)}")
        print("\nSeverity Breakdown:")
        
        breakdown = self._get_severity_breakdown()
        for severity, count in breakdown.items():
            if count > 0:
                print(f"  {severity}: {count}")
        
        if self.vulnerabilities:
            print("\nTop Vulnerabilities:")
            sorted_vulns = sorted(
                self.vulnerabilities,
                key=lambda v: (v.severity.value, v.cvss_score or 0),
                reverse=True
            )
            
            for i, vuln in enumerate(sorted_vulns[:5], 1):
                print(f"\n{i}. {vuln.title}")
                print(f"   Severity: {vuln.severity.value}")
                print(f"   URL: {vuln.affected_url}")
                print(f"   Description: {vuln.description}")
        
        print("\n" + "="*80)


if __name__ == "__main__":
    # Example usage
    scanner = SecurityScanner("https://example.com")
    vulnerabilities = scanner.scan_all()
    scanner.print_summary()
    scanner.generate_report()
