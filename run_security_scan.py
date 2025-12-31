#!/usr/bin/env python3
"""
Security Scan Runner
====================
Main script to run complete security analysis.

Usage:
    python run_security_scan.py --target https://your-app.com
    python run_security_scan.py --api https://api.your-app.com --secrets ./src

Author: Jason Teixeira
"""

import argparse
import logging
from security_scanner import SecurityScanner
from api_security import APISecurityTester
from secrets_detector import SecretsDetector

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(
        description='Run comprehensive security analysis'
    )
    
    parser.add_argument(
        '--target',
        help='Target web application URL',
        default='https://example.com'
    )
    
    parser.add_argument(
        '--api',
        help='API base URL for API security tests',
        default=None
    )
    
    parser.add_argument(
        '--secrets',
        help='Directory to scan for secrets',
        default='./'
    )
    
    parser.add_argument(
        '--skip-web',
        action='store_true',
        help='Skip web application security tests'
    )
    
    parser.add_argument(
        '--skip-api',
        action='store_true',
        help='Skip API security tests'
    )
    
    parser.add_argument(
        '--skip-secrets',
        action='store_true',
        help='Skip secrets detection'
    )
    
    args = parser.parse_args()
    
    total_vulnerabilities = 0
    
    # Run web application security scan
    if not args.skip_web:
        logger.info("="*80)
        logger.info("STARTING WEB APPLICATION SECURITY SCAN")
        logger.info("="*80)
        
        scanner = SecurityScanner(args.target)
        web_vulns = scanner.scan_all()
        scanner.print_summary()
        scanner.generate_report("web_security_report.json")
        
        total_vulnerabilities += len(web_vulns)
        logger.info(f"Web scan complete. Found {len(web_vulns)} vulnerabilities.")
    
    # Run API security tests
    if args.api and not args.skip_api:
        logger.info("\n" + "="*80)
        logger.info("STARTING API SECURITY TESTS")
        logger.info("="*80)
        
        api_tester = APISecurityTester(args.api)
        api_vulns = api_tester.test_all()
        api_tester.generate_report("api_security_report.json")
        
        total_vulnerabilities += len(api_vulns)
        logger.info(f"API scan complete. Found {len(api_vulns)} vulnerabilities.")
    
    # Run secrets detection
    if not args.skip_secrets:
        logger.info("\n" + "="*80)
        logger.info("STARTING SECRETS DETECTION")
        logger.info("="*80)
        
        detector = SecretsDetector(args.secrets)
        secrets = detector.scan()
        detector.print_summary()
        detector.generate_report("secrets_report.json")
        
        total_vulnerabilities += len(secrets)
        logger.info(f"Secrets scan complete. Found {len(secrets)} potential secrets.")
    
    # Final summary
    logger.info("\n" + "="*80)
    logger.info("SECURITY SCAN COMPLETE")
    logger.info("="*80)
    logger.info(f"Total Issues Found: {total_vulnerabilities}")
    logger.info("\nReports generated:")
    logger.info("  - web_security_report.json")
    if args.api:
        logger.info("  - api_security_report.json")
    logger.info("  - secrets_report.json")
    logger.info("="*80)


if __name__ == "__main__":
    main()
