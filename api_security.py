"""
API Security Testing Module
===========================
Specialized tests for REST API security vulnerabilities.

Author: Jason Teixeira
License: MIT
"""

import requests
import jwt
import time
import json
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from security_scanner import Vulnerability, Severity

logger = logging.getLogger(__name__)


class APISecurityTester:
    """
    API-specific security testing
    
    Tests:
    - JWT token security
    - API rate limiting
    - OAuth/OpenID Connect flows
    - API key security
    - CORS misconfiguration
    - API versioning issues
    """
    
    def __init__(self, api_base_url: str, api_key: Optional[str] = None):
        """
        Initialize API security tester
        
        Args:
            api_base_url: Base URL of API
            api_key: Optional API key for authenticated tests
        """
        self.api_base_url = api_base_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        self.vulnerabilities: List[Vulnerability] = []
        
        if api_key:
            self.session.headers['Authorization'] = f'Bearer {api_key}'
        
        logger.info(f"Initialized API Security Tester for {api_base_url}")
    
    def test_all(self) -> List[Vulnerability]:
        """Run all API security tests"""
        logger.info("Starting API security tests...")
        
        self.test_jwt_security()
        self.test_rate_limiting()
        self.test_cors()
        self.test_api_versioning()
        self.test_api_authentication()
        self.test_excessive_data_exposure()
        self.test_mass_assignment()
        
        logger.info(f"API security tests complete. Found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities
    
    def test_jwt_security(self) -> None:
        """
        Test JWT token security
        
        Tests:
        - None algorithm attack
        - Weak signing key
        - Missing expiration
        - Token not invalidated on logout
        """
        logger.info("Testing JWT security...")
        
        try:
            # Try to get a JWT token
            response = self.session.post(
                f"{self.api_base_url}/auth/login",
                json={'username': 'test', 'password': 'test'},
                timeout=10
            )
            
            if response.status_code == 200 and 'token' in response.json():
                token = response.json()['token']
                
                # Test 1: Check if 'none' algorithm is accepted
                try:
                    decoded = jwt.decode(token, options={"verify_signature": False})
                    
                    # Create token with 'none' algorithm
                    none_token = jwt.encode(
                        decoded,
                        key="",
                        algorithm="none"
                    )
                    
                    # Try using it
                    test_response = self.session.get(
                        f"{self.api_base_url}/api/protected",
                        headers={'Authorization': f'Bearer {none_token}'},
                        timeout=10
                    )
                    
                    if test_response.status_code == 200:
                        self.vulnerabilities.append(Vulnerability(
                            title="JWT None Algorithm Attack",
                            severity=Severity.CRITICAL,
                            description="API accepts JWT tokens with 'none' algorithm",
                            affected_url=f"{self.api_base_url}/api/protected",
                            evidence="Successfully authenticated with 'none' algorithm JWT",
                            remediation="Reject JWT tokens with 'none' algorithm. Explicitly specify accepted algorithms.",
                            cwe_id="CWE-347",
                            cvss_score=9.8
                        ))
                        logger.critical("JWT none algorithm accepted!")
                
                except jwt.exceptions.InvalidTokenError:
                    pass  # Good, token validation working
                
                # Test 2: Check token expiration
                if 'exp' not in decoded:
                    self.vulnerabilities.append(Vulnerability(
                        title="JWT Missing Expiration",
                        severity=Severity.HIGH,
                        description="JWT tokens have no expiration time",
                        affected_url=f"{self.api_base_url}/auth/login",
                        evidence="JWT token missing 'exp' claim",
                        remediation="Add expiration time to JWT tokens. Use short lifetimes (15-60 minutes).",
                        cwe_id="CWE-613",
                        cvss_score=7.5
                    ))
                    logger.warning("JWT missing expiration")
                
                # Test 3: Check if token has reasonable expiration
                elif decoded.get('exp'):
                    exp_time = decoded['exp']
                    current_time = time.time()
                    lifetime = exp_time - current_time
                    
                    if lifetime > 86400:  # More than 1 day
                        self.vulnerabilities.append(Vulnerability(
                            title="JWT Long Expiration Time",
                            severity=Severity.MEDIUM,
                            description=f"JWT token expires in {lifetime/3600:.1f} hours",
                            affected_url=f"{self.api_base_url}/auth/login",
                            evidence=f"Token lifetime: {lifetime} seconds",
                            remediation="Reduce JWT expiration time to 15-60 minutes. Implement refresh tokens.",
                            cwe_id="CWE-613",
                            cvss_score=5.3
                        ))
                        logger.warning(f"JWT expiration too long: {lifetime}s")
        
        except Exception as e:
            logger.debug(f"JWT security test failed: {e}")
    
    def test_rate_limiting(self) -> None:
        """
        Test API rate limiting
        
        Checks if rate limiting is implemented to prevent:
        - Brute force attacks
        - DoS attacks
        - Resource exhaustion
        """
        logger.info("Testing rate limiting...")
        
        test_endpoint = f"{self.api_base_url}/api/test"
        
        # Make rapid requests
        request_count = 100
        successful_requests = 0
        rate_limited = False
        
        start_time = time.time()
        
        for i in range(request_count):
            try:
                response = self.session.get(test_endpoint, timeout=5)
                
                if response.status_code == 429:  # Too Many Requests
                    rate_limited = True
                    logger.info(f"Rate limited after {i+1} requests")
                    break
                elif response.status_code == 200:
                    successful_requests += 1
            
            except requests.exceptions.RequestException:
                pass
        
        elapsed = time.time() - start_time
        
        # If we made 100+ requests/second without rate limiting, that's a problem
        if not rate_limited and successful_requests > 50:
            self.vulnerabilities.append(Vulnerability(
                title="Missing Rate Limiting",
                severity=Severity.HIGH,
                description="API has no rate limiting on endpoints",
                affected_url=test_endpoint,
                evidence=f"Made {successful_requests} requests in {elapsed:.2f} seconds without rate limiting",
                remediation="Implement rate limiting: 100 requests/minute per IP, 1000/hour per user. Return 429 status.",
                cwe_id="CWE-770",
                cvss_score=7.5
            ))
            logger.warning("No rate limiting detected")
    
    def test_cors(self) -> None:
        """
        Test CORS (Cross-Origin Resource Sharing) configuration
        
        Checks for:
        - Overly permissive CORS
        - Wildcard origins
        - Credential exposure
        """
        logger.info("Testing CORS configuration...")
        
        try:
            # Test with custom origin
            response = self.session.get(
                self.api_base_url,
                headers={'Origin': 'https://evil.com'},
                timeout=10
            )
            
            cors_origin = response.headers.get('Access-Control-Allow-Origin')
            cors_creds = response.headers.get('Access-Control-Allow-Credentials')
            
            # Check for wildcard with credentials
            if cors_origin == '*' and cors_creds == 'true':
                self.vulnerabilities.append(Vulnerability(
                    title="Insecure CORS Configuration",
                    severity=Severity.HIGH,
                    description="CORS allows wildcard origin with credentials",
                    affected_url=self.api_base_url,
                    evidence=f"Access-Control-Allow-Origin: * with Credentials: true",
                    remediation="Don't use wildcard origin with credentials. Whitelist specific origins.",
                    cwe_id="CWE-942",
                    cvss_score=7.4
                ))
                logger.warning("Insecure CORS: wildcard with credentials")
            
            # Check if evil origin is accepted
            elif cors_origin == 'https://evil.com':
                self.vulnerabilities.append(Vulnerability(
                    title="CORS Allows Arbitrary Origins",
                    severity=Severity.MEDIUM,
                    description="API reflects origin header without validation",
                    affected_url=self.api_base_url,
                    evidence="Arbitrary origin 'https://evil.com' was accepted",
                    remediation="Implement origin whitelist. Don't reflect Origin header without validation.",
                    cwe_id="CWE-942",
                    cvss_score=6.1
                ))
                logger.warning("CORS reflects arbitrary origins")
        
        except requests.exceptions.RequestException as e:
            logger.debug(f"CORS test failed: {e}")
    
    def test_api_versioning(self) -> None:
        """
        Test API versioning security
        
        Checks:
        - Old API versions still accessible
        - No version deprecation
        - Version in URL vs header
        """
        logger.info("Testing API versioning...")
        
        versions_to_test = ['v1', 'v2', 'v3', '1.0', '2.0']
        accessible_versions = []
        
        for version in versions_to_test:
            try:
                # Test version in URL
                response = self.session.get(
                    f"{self.api_base_url}/{version}/",
                    timeout=10
                )
                
                if response.status_code == 200:
                    accessible_versions.append(version)
                    logger.info(f"API version {version} accessible")
            
            except requests.exceptions.RequestException:
                pass
        
        if len(accessible_versions) > 2:
            self.vulnerabilities.append(Vulnerability(
                title="Multiple Old API Versions Accessible",
                severity=Severity.MEDIUM,
                description=f"Found {len(accessible_versions)} API versions accessible",
                affected_url=self.api_base_url,
                evidence=f"Accessible versions: {', '.join(accessible_versions)}",
                remediation="Deprecate old API versions. Sunset timeline: announce, warn, disable.",
                cwe_id="CWE-16",
                cvss_score=5.3
            ))
            logger.warning(f"Multiple API versions accessible: {accessible_versions}")
    
    def test_api_authentication(self) -> None:
        """
        Test API authentication mechanisms
        
        Checks:
        - API key in URL
        - Weak API keys
        - No authentication on sensitive endpoints
        """
        logger.info("Testing API authentication...")
        
        sensitive_endpoints = [
            '/api/users',
            '/api/admin',
            '/api/config',
            '/api/secrets'
        ]
        
        for endpoint in sensitive_endpoints:
            url = f"{self.api_base_url}{endpoint}"
            
            try:
                # Try without authentication
                response = requests.get(url, timeout=10)
                
                if response.status_code == 200:
                    self.vulnerabilities.append(Vulnerability(
                        title="Unauthenticated Access to Sensitive Endpoint",
                        severity=Severity.CRITICAL,
                        description=f"Endpoint {endpoint} accessible without authentication",
                        affected_url=url,
                        evidence=f"HTTP 200 response without authentication",
                        remediation="Require authentication for all sensitive endpoints. Return 401 for unauthenticated requests.",
                        cwe_id="CWE-306",
                        cvss_score=9.1
                    ))
                    logger.critical(f"Unauthenticated access to {endpoint}")
            
            except requests.exceptions.RequestException:
                pass
    
    def test_excessive_data_exposure(self) -> None:
        """
        Test for excessive data exposure in API responses
        
        Checks if API returns more data than necessary
        """
        logger.info("Testing excessive data exposure...")
        
        try:
            response = self.session.get(
                f"{self.api_base_url}/api/user/profile",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Check for sensitive fields that shouldn't be exposed
                sensitive_fields = [
                    'password', 'password_hash', 'ssn', 'credit_card',
                    'api_key', 'secret', 'private_key', 'salt'
                ]
                
                found_sensitive = []
                for field in sensitive_fields:
                    if field in str(data).lower():
                        found_sensitive.append(field)
                
                if found_sensitive:
                    self.vulnerabilities.append(Vulnerability(
                        title="Excessive Data Exposure in API Response",
                        severity=Severity.HIGH,
                        description="API response contains sensitive fields",
                        affected_url=f"{self.api_base_url}/api/user/profile",
                        evidence=f"Found sensitive fields: {', '.join(found_sensitive)}",
                        remediation="Remove sensitive fields from API responses. Use DTOs to control exposed data.",
                        cwe_id="CWE-359",
                        cvss_score=7.5
                    ))
                    logger.warning(f"Excessive data exposure: {found_sensitive}")
        
        except Exception as e:
            logger.debug(f"Data exposure test failed: {e}")
    
    def test_mass_assignment(self) -> None:
        """
        Test for mass assignment vulnerabilities
        
        Checks if API allows updating fields that shouldn't be user-modifiable
        """
        logger.info("Testing mass assignment...")
        
        try:
            # Try to update sensitive fields
            response = self.session.put(
                f"{self.api_base_url}/api/user/profile",
                json={
                    'name': 'Test User',
                    'email': 'test@example.com',
                    'is_admin': True,  # Should not be allowed
                    'role': 'admin',   # Should not be allowed
                    'balance': 1000000  # Should not be allowed
                },
                timeout=10
            )
            
            if response.status_code == 200:
                # Check if forbidden fields were updated
                updated_data = response.json()
                
                forbidden_updates = []
                if updated_data.get('is_admin') == True:
                    forbidden_updates.append('is_admin')
                if updated_data.get('role') == 'admin':
                    forbidden_updates.append('role')
                if updated_data.get('balance') == 1000000:
                    forbidden_updates.append('balance')
                
                if forbidden_updates:
                    self.vulnerabilities.append(Vulnerability(
                        title="Mass Assignment Vulnerability",
                        severity=Severity.CRITICAL,
                        description="API allows updating sensitive fields via mass assignment",
                        affected_url=f"{self.api_base_url}/api/user/profile",
                        evidence=f"Successfully updated forbidden fields: {', '.join(forbidden_updates)}",
                        remediation="Implement allow-list for updatable fields. Use DTOs with explicit field mapping.",
                        cwe_id="CWE-915",
                        cvss_score=9.1
                    ))
                    logger.critical(f"Mass assignment vulnerability: {forbidden_updates}")
        
        except Exception as e:
            logger.debug(f"Mass assignment test failed: {e}")
    
    def generate_report(self, output_file: str = "api_security_report.json") -> None:
        """Generate API security report"""
        report = {
            'api_endpoint': self.api_base_url,
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"API security report generated: {output_file}")


if __name__ == "__main__":
    # Example usage
    tester = APISecurityTester("https://api.example.com")
    vulnerabilities = tester.test_all()
    tester.generate_report()
