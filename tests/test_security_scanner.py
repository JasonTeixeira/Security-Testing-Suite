"""
Test Suite for Security Scanner
================================
Comprehensive tests for OWASP Top 10 security scanner.

Author: Jason Teixeira
License: MIT
"""

import pytest
import requests
from unittest.mock import Mock, patch, MagicMock
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from security_scanner import SecurityScanner, Vulnerability, Severity


class TestSecurityScanner:
    """Test suite for SecurityScanner class"""
    
    @pytest.fixture
    def scanner(self):
        """Create scanner instance for testing"""
        return SecurityScanner("https://test.example.com")
    
    @pytest.fixture
    def mock_response(self):
        """Create mock HTTP response"""
        response = Mock(spec=requests.Response)
        response.status_code = 200
        response.text = "<html>Test content</html>"
        response.headers = {'Content-Type': 'text/html'}
        response.json.return_value = {'status': 'ok'}
        return response
    
    def test_scanner_initialization(self, scanner):
        """Test scanner initializes correctly"""
        assert scanner.target_url == "https://test.example.com"
        assert scanner.session is not None
        assert len(scanner.vulnerabilities) == 0
    
    def test_sql_injection_detection(self, scanner, mock_response):
        """Test SQL injection vulnerability detection"""
        # Simulate SQL error in response
        mock_response.text = "SQL syntax error near 'OR 1=1'"
        
        with patch.object(scanner.session, 'get', return_value=mock_response):
            scanner.test_sql_injection()
        
        # Should detect SQL injection
        sql_vulns = [v for v in scanner.vulnerabilities 
                    if v.title == "SQL Injection Vulnerability"]
        assert len(sql_vulns) > 0
        assert sql_vulns[0].severity == Severity.CRITICAL
    
    def test_xss_detection_reflected(self, scanner, mock_response):
        """Test reflected XSS detection"""
        payload = "<script>alert('XSS')</script>"
        mock_response.text = f"Search results for: {payload}"
        
        with patch.object(scanner.session, 'get', return_value=mock_response):
            scanner.test_xss()
        
        # Should detect XSS
        xss_vulns = [v for v in scanner.vulnerabilities 
                    if "XSS" in v.title]
        assert len(xss_vulns) > 0
    
    def test_xss_detection_properly_encoded(self, scanner, mock_response):
        """Test that properly encoded output doesn't trigger XSS"""
        payload = "<script>alert('XSS')</script>"
        mock_response.text = "&lt;script&gt;alert('XSS')&lt;/script&gt;"
        
        with patch.object(scanner.session, 'get', return_value=mock_response):
            scanner.test_xss()
        
        # Should NOT detect XSS (properly encoded)
        xss_vulns = [v for v in scanner.vulnerabilities 
                    if "XSS" in v.title]
        assert len(xss_vulns) == 0
    
    def test_https_enforcement(self):
        """Test HTTPS enforcement check"""
        # HTTP URL should be flagged
        http_scanner = SecurityScanner("http://insecure.com")
        http_scanner.test_sensitive_data_exposure()
        
        https_vulns = [v for v in http_scanner.vulnerabilities 
                      if "HTTPS" in v.title]
        assert len(https_vulns) > 0
        assert https_vulns[0].severity == Severity.HIGH
    
    def test_security_headers_detection(self, scanner, mock_response):
        """Test detection of missing security headers"""
        # Response without security headers
        mock_response.headers = {
            'Content-Type': 'text/html',
            'Server': 'Apache/2.4.41'
        }
        
        with patch.object(scanner.session, 'get', return_value=mock_response):
            scanner.test_security_misconfiguration()
        
        # Should detect missing headers
        header_vulns = [v for v in scanner.vulnerabilities 
                       if "Missing Security Header" in v.title]
        assert len(header_vulns) > 0
    
    def test_session_cookie_security(self, scanner, mock_response):
        """Test session cookie security checks"""
        # Create insecure cookie
        scanner.session.cookies.set(
            'session_id',
            'abc123',
            secure=False,
            httponly=False
        )
        
        with patch.object(scanner.session, 'get', return_value=mock_response):
            scanner._test_session_security()
        
        # Should detect insecure cookie
        cookie_vulns = [v for v in scanner.vulnerabilities 
                       if "Cookie" in v.title]
        assert len(cookie_vulns) > 0
    
    def test_generate_report(self, scanner, tmp_path):
        """Test report generation"""
        # Add some test vulnerabilities
        scanner.vulnerabilities.append(Vulnerability(
            title="Test Vulnerability",
            severity=Severity.HIGH,
            description="Test description",
            affected_url="https://test.com",
            evidence="Test evidence",
            remediation="Test remediation"
        ))
        
        report_file = tmp_path / "test_report.json"
        scanner.generate_report(str(report_file))
        
        assert report_file.exists()
        
        import json
        with open(report_file) as f:
            report = json.load(f)
        
        assert report['total_vulnerabilities'] == 1
        assert 'vulnerabilities' in report
        assert len(report['vulnerabilities']) == 1
    
    def test_severity_breakdown(self, scanner):
        """Test severity breakdown calculation"""
        scanner.vulnerabilities = [
            Vulnerability("V1", Severity.CRITICAL, "d", "u", "e", "r"),
            Vulnerability("V2", Severity.HIGH, "d", "u", "e", "r"),
            Vulnerability("V3", Severity.HIGH, "d", "u", "e", "r"),
            Vulnerability("V4", Severity.MEDIUM, "d", "u", "e", "r"),
        ]
        
        breakdown = scanner._get_severity_breakdown()
        
        assert breakdown['CRITICAL'] == 1
        assert breakdown['HIGH'] == 2
        assert breakdown['MEDIUM'] == 1
        assert breakdown['LOW'] == 0
    
    def test_detect_sql_injection_errors(self, scanner):
        """Test SQL error detection"""
        response = Mock(spec=requests.Response)
        
        # Test various SQL error patterns
        sql_errors = [
            "SQL syntax error",
            "mysql_fetch_array() expects",
            "PostgreSQL query failed",
            "ORA-01756",
            "SQLite3::SQLException"
        ]
        
        for error in sql_errors:
            response.text = f"Error: {error} in query"
            assert scanner._detect_sql_injection(response) == True
    
    def test_no_false_positive_sql_injection(self, scanner):
        """Test that normal content doesn't trigger SQL injection"""
        response = Mock(spec=requests.Response)
        response.text = "Normal page content without SQL errors"
        
        assert scanner._detect_sql_injection(response) == False


class TestVulnerability:
    """Test Vulnerability dataclass"""
    
    def test_vulnerability_creation(self):
        """Test creating vulnerability"""
        vuln = Vulnerability(
            title="Test Vulnerability",
            severity=Severity.HIGH,
            description="Test description",
            affected_url="https://test.com",
            evidence="Test evidence",
            remediation="Fix this",
            cwe_id="CWE-79",
            cvss_score=7.5
        )
        
        assert vuln.title == "Test Vulnerability"
        assert vuln.severity == Severity.HIGH
        assert vuln.cwe_id == "CWE-79"
        assert vuln.cvss_score == 7.5
    
    def test_vulnerability_to_dict(self):
        """Test converting vulnerability to dictionary"""
        vuln = Vulnerability(
            title="Test",
            severity=Severity.MEDIUM,
            description="Desc",
            affected_url="URL",
            evidence="Evidence",
            remediation="Fix"
        )
        
        vuln_dict = vuln.to_dict()
        
        assert vuln_dict['title'] == "Test"
        assert vuln_dict['severity'] == "MEDIUM"
        assert vuln_dict['description'] == "Desc"


class TestIntegration:
    """Integration tests for security scanner"""
    
    @pytest.mark.slow
    def test_full_scan_workflow(self):
        """Test complete scan workflow"""
        scanner = SecurityScanner("https://example.com")
        
        # Run limited scan (avoid actual network calls in tests)
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = Mock(spec=requests.Response)
            mock_response.status_code = 200
            mock_response.text = "Test"
            mock_response.headers = {}
            mock_get.return_value = mock_response
            
            # Run scan
            vulnerabilities = scanner.scan_all()
        
        # Should have run all tests
        assert isinstance(vulnerabilities, list)
    
    def test_print_summary(self, scanner, capsys):
        """Test summary printing"""
        scanner.vulnerabilities.append(
            Vulnerability("Test", Severity.HIGH, "d", "u", "e", "r")
        )
        
        scanner.print_summary()
        
        captured = capsys.readouterr()
        assert "SECURITY SCAN SUMMARY" in captured.out
        assert "Total Vulnerabilities: 1" in captured.out


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
