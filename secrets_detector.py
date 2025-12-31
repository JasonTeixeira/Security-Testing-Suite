"""
Secrets Detection Module
========================
Detects hardcoded secrets, API keys, and sensitive data in code.

Author: Jason Teixeira
License: MIT
"""

import re
import os
import json
import logging
from typing import List, Dict, Optional, Set
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class SecretType(Enum):
    """Types of secrets that can be detected"""
    AWS_ACCESS_KEY = "AWS Access Key"
    AWS_SECRET_KEY = "AWS Secret Key"
    GOOGLE_API_KEY = "Google API Key"
    SLACK_TOKEN = "Slack Token"
    GITHUB_TOKEN = "GitHub Token"
    PRIVATE_KEY = "Private Key"
    GENERIC_API_KEY = "Generic API Key"
    GENERIC_SECRET = "Generic Secret"
    PASSWORD = "Password"
    JWT_TOKEN = "JWT Token"
    DATABASE_URL = "Database Connection String"
    STRIPE_KEY = "Stripe API Key"


@dataclass
class SecretMatch:
    """Represents a detected secret"""
    secret_type: SecretType
    file_path: str
    line_number: int
    line_content: str
    matched_value: str
    confidence: str  # HIGH, MEDIUM, LOW
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'type': self.secret_type.value,
            'file': self.file_path,
            'line': self.line_number,
            'content': self.line_content[:100],  # Truncate for safety
            'confidence': self.confidence
        }


class SecretsDetector:
    """
    Detects hardcoded secrets in source code
    
    Uses regex patterns to find:
    - API keys
    - Passwords
    - Private keys
    - Database credentials
    - OAuth tokens
    """
    
    # Regex patterns for different secret types
    PATTERNS = {
        SecretType.AWS_ACCESS_KEY: [
            r'AKIA[0-9A-Z]{16}',
            r'aws_access_key_id\s*=\s*["\']([A-Z0-9]{20})["\']'
        ],
        SecretType.AWS_SECRET_KEY: [
            r'aws_secret_access_key\s*=\s*["\']([A-Za-z0-9/+=]{40})["\']'
        ],
        SecretType.GOOGLE_API_KEY: [
            r'AIza[0-9A-Za-z\-_]{35}'
        ],
        SecretType.SLACK_TOKEN: [
            r'xox[baprs]-([0-9a-zA-Z]{10,48})'
        ],
        SecretType.GITHUB_TOKEN: [
            r'ghp_[0-9a-zA-Z]{36}',
            r'github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}'
        ],
        SecretType.PRIVATE_KEY: [
            r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
        ],
        SecretType.GENERIC_API_KEY: [
            r'api[_-]?key\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            r'apikey\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']'
        ],
        SecretType.GENERIC_SECRET: [
            r'secret\s*[=:]\s*["\']([^"\']{20,})["\']',
            r'client_secret\s*[=:]\s*["\']([^"\']{20,})["\']'
        ],
        SecretType.PASSWORD: [
            r'password\s*[=:]\s*["\']([^"\']{8,})["\']',
            r'passwd\s*[=:]\s*["\']([^"\']{8,})["\']'
        ],
        SecretType.JWT_TOKEN: [
            r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
        ],
        SecretType.DATABASE_URL: [
            r'(postgres|mysql|mongodb)://[^:\s]+:[^@\s]+@[^:\s]+:\d+/\w+',
            r'jdbc:[a-z]+://[^:\s]+:[^@\s]+@[^/\s]+/\w+'
        ],
        SecretType.STRIPE_KEY: [
            r'sk_live_[0-9a-zA-Z]{24}',
            r'pk_live_[0-9a-zA-Z]{24}'
        ]
    }
    
    # Patterns that indicate false positives
    FALSE_POSITIVE_PATTERNS = [
        r'example\.com',
        r'your[-_]?api[-_]?key',
        r'your[-_]?secret',
        r'<API[-_]?KEY>',
        r'INSERT[-_]?API[-_]?KEY',
        r'TODO',
        r'FIXME',
        r'xxx+',
        r'test[-_]?key',
        r'dummy[-_]?key',
        r'fake[-_]?key',
        r'placeholder'
    ]
    
    # File extensions to scan
    SCANNABLE_EXTENSIONS = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go',
        '.rb', '.php', '.cs', '.swift', '.kt', '.rs',
        '.yml', '.yaml', '.json', '.xml', '.env', '.config',
        '.sh', '.bash', '.zsh', '.properties', '.ini', '.toml'
    }
    
    # Directories to skip
    SKIP_DIRECTORIES = {
        'node_modules', '.git', '.svn', '__pycache__', 'venv',
        'env', '.env', 'dist', 'build', 'target', '.pytest_cache',
        '.vscode', '.idea', 'vendor'
    }
    
    def __init__(self, root_path: str):
        """
        Initialize secrets detector
        
        Args:
            root_path: Root directory to scan
        """
        self.root_path = Path(root_path)
        self.secrets: List[SecretMatch] = []
        self.scanned_files = 0
        self.skipped_files = 0
        
        logger.info(f"Initialized SecretsDetector for {root_path}")
    
    def scan(self) -> List[SecretMatch]:
        """
        Scan directory for secrets
        
        Returns:
            List of detected secrets
        """
        logger.info("Starting secrets scan...")
        
        for file_path in self._get_scannable_files():
            self._scan_file(file_path)
        
        logger.info(
            f"Scan complete. Scanned {self.scanned_files} files, "
            f"skipped {self.skipped_files} files, "
            f"found {len(self.secrets)} potential secrets"
        )
        
        return self.secrets
    
    def _get_scannable_files(self) -> List[Path]:
        """Get list of files to scan"""
        scannable_files = []
        
        for file_path in self.root_path.rglob('*'):
            # Skip directories
            if file_path.is_dir():
                continue
            
            # Skip if in excluded directory
            if any(skip_dir in file_path.parts for skip_dir in self.SKIP_DIRECTORIES):
                self.skipped_files += 1
                continue
            
            # Check if extension is scannable
            if file_path.suffix in self.SCANNABLE_EXTENSIONS:
                scannable_files.append(file_path)
            else:
                self.skipped_files += 1
        
        return scannable_files
    
    def _scan_file(self, file_path: Path) -> None:
        """Scan a single file for secrets"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line_number, line in enumerate(lines, start=1):
                self._scan_line(file_path, line_number, line)
            
            self.scanned_files += 1
        
        except Exception as e:
            logger.debug(f"Error scanning {file_path}: {e}")
            self.skipped_files += 1
    
    def _scan_line(self, file_path: Path, line_number: int, line: str) -> None:
        """Scan a single line for secrets"""
        # Check each pattern type
        for secret_type, patterns in self.PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                
                for match in matches:
                    matched_value = match.group(0)
                    
                    # Check if it's a false positive
                    if self._is_false_positive(line, matched_value):
                        continue
                    
                    # Determine confidence
                    confidence = self._calculate_confidence(
                        secret_type,
                        matched_value,
                        line
                    )
                    
                    # Add to results
                    self.secrets.append(SecretMatch(
                        secret_type=secret_type,
                        file_path=str(file_path.relative_to(self.root_path)),
                        line_number=line_number,
                        line_content=line.strip(),
                        matched_value=self._redact_secret(matched_value),
                        confidence=confidence
                    ))
                    
                    logger.warning(
                        f"Found {secret_type.value} in {file_path}:{line_number}"
                    )
    
    def _is_false_positive(self, line: str, matched_value: str) -> bool:
        """
        Check if match is likely a false positive
        
        Args:
            line: The line containing the match
            matched_value: The matched secret value
            
        Returns:
            True if likely false positive
        """
        # Check against false positive patterns
        for pattern in self.FALSE_POSITIVE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                return True
            if re.search(pattern, matched_value, re.IGNORECASE):
                return True
        
        # Check for common test/example indicators
        if any(indicator in line.lower() for indicator in [
            'example', 'sample', 'test', 'mock', 'fake', 'dummy'
        ]):
            return True
        
        # Check if in comment
        if line.strip().startswith(('#', '//', '/*', '*', '--')):
            return True
        
        return False
    
    def _calculate_confidence(
        self,
        secret_type: SecretType,
        matched_value: str,
        line: str
    ) -> str:
        """
        Calculate confidence level for detection
        
        Args:
            secret_type: Type of secret detected
            matched_value: The matched value
            line: The line containing the match
            
        Returns:
            Confidence level: HIGH, MEDIUM, or LOW
        """
        # High confidence for well-known formats
        high_confidence_types = {
            SecretType.AWS_ACCESS_KEY,
            SecretType.PRIVATE_KEY,
            SecretType.JWT_TOKEN,
            SecretType.STRIPE_KEY,
            SecretType.GITHUB_TOKEN
        }
        
        if secret_type in high_confidence_types:
            return "HIGH"
        
        # Medium confidence for generic patterns with good indicators
        if any(keyword in line.lower() for keyword in ['key', 'token', 'secret', 'password']):
            if len(matched_value) >= 32:  # Long enough to be real
                return "MEDIUM"
        
        return "LOW"
    
    def _redact_secret(self, secret: str) -> str:
        """
        Redact secret for safe logging
        
        Args:
            secret: The secret to redact
            
        Returns:
            Redacted version
        """
        if len(secret) <= 8:
            return "***REDACTED***"
        
        # Show first 4 and last 4 characters
        return f"{secret[:4]}...{secret[-4:]}"
    
    def generate_report(self, output_file: str = "secrets_report.json") -> None:
        """
        Generate secrets detection report
        
        Args:
            output_file: Output file path
        """
        # Group by file
        secrets_by_file: Dict[str, List[SecretMatch]] = {}
        for secret in self.secrets:
            if secret.file_path not in secrets_by_file:
                secrets_by_file[secret.file_path] = []
            secrets_by_file[secret.file_path].append(secret)
        
        # Group by type
        secrets_by_type: Dict[str, int] = {}
        for secret in self.secrets:
            type_name = secret.secret_type.value
            secrets_by_type[type_name] = secrets_by_type.get(type_name, 0) + 1
        
        report = {
            'summary': {
                'total_secrets': len(self.secrets),
                'files_scanned': self.scanned_files,
                'files_skipped': self.skipped_files,
                'files_with_secrets': len(secrets_by_file)
            },
            'by_type': secrets_by_type,
            'by_confidence': {
                'HIGH': len([s for s in self.secrets if s.confidence == 'HIGH']),
                'MEDIUM': len([s for s in self.secrets if s.confidence == 'MEDIUM']),
                'LOW': len([s for s in self.secrets if s.confidence == 'LOW'])
            },
            'findings': [s.to_dict() for s in self.secrets]
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Secrets report generated: {output_file}")
    
    def print_summary(self) -> None:
        """Print summary to console"""
        print("\n" + "="*80)
        print("SECRETS DETECTION SUMMARY")
        print("="*80)
        print(f"Files Scanned: {self.scanned_files}")
        print(f"Files Skipped: {self.skipped_files}")
        print(f"Potential Secrets Found: {len(self.secrets)}")
        
        if self.secrets:
            print("\nBy Confidence Level:")
            high = len([s for s in self.secrets if s.confidence == 'HIGH'])
            medium = len([s for s in self.secrets if s.confidence == 'MEDIUM'])
            low = len([s for s in self.secrets if s.confidence == 'LOW'])
            
            print(f"  HIGH:   {high}")
            print(f"  MEDIUM: {medium}")
            print(f"  LOW:    {low}")
            
            print("\nBy Secret Type:")
            secret_types = {}
            for secret in self.secrets:
                type_name = secret.secret_type.value
                secret_types[type_name] = secret_types.get(type_name, 0) + 1
            
            for secret_type, count in sorted(
                secret_types.items(),
                key=lambda x: x[1],
                reverse=True
            ):
                print(f"  {secret_type}: {count}")
            
            print("\nTop Findings:")
            high_confidence = [s for s in self.secrets if s.confidence == 'HIGH']
            for i, secret in enumerate(high_confidence[:5], 1):
                print(f"\n{i}. {secret.secret_type.value}")
                print(f"   File: {secret.file_path}:{secret.line_number}")
                print(f"   Confidence: {secret.confidence}")
        
        print("\n" + "="*80)


if __name__ == "__main__":
    # Example usage
    detector = SecretsDetector("./")
    secrets = detector.scan()
    detector.print_summary()
    detector.generate_report()
