"""
Content Inspector for Data Loss Prevention (DLP)
Scans file content for sensitive keywords, patterns, and data types.
"""
import os
import re
from typing import Tuple, List, Dict, Optional


class ContentInspector:
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize content inspector with configuration.
        
        Args:
            config: Dictionary containing inspection settings
        """
        self.config = config or {}
        self.inspection_config = self.config.get("content_inspection", {})
        
        # Default sensitive keywords
        self.sensitive_keywords = self.inspection_config.get(
            "sensitive_keywords",
            ["password", "confidential", "private key", "secret", "api key", 
             "access token", "credit card", "ssn", "social security"]
        )
        
        # Default sensitive patterns (regex)
        self.sensitive_patterns = self.inspection_config.get(
            "sensitive_patterns",
            [
                r'\bpassword\s*[:=]\s*\S+',  # password: xyz or password=xyz
                r'\bconfidential\b',
                r'\bprivate\s+key\b',
                r'\bsecret\s*[:=]\s*\S+',
                r'\bapi[_-]?key\s*[:=]\s*\S+',
                r'\baccess[_-]?token\s*[:=]\s*\S+',
            ]
        )
        
        # Data type patterns
        self.data_patterns = {
            "credit_card": r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
            "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        }
        
        # Enable/disable specific data type detection
        self.enabled_data_types = self.inspection_config.get(
            "enabled_data_types",
            ["credit_card", "ssn"]
        )
    
    def inspect_content(self, filepath: str) -> Tuple[bool, str, List[str]]:
        """
        Inspect file content for sensitive data.
        
        Args:
            filepath: Path to the file to inspect
            
        Returns:
            Tuple of (safe: bool, message: str, findings: List[str])
        """
        if not self.inspection_config.get("enabled", False):
            return True, "OK", []
        
        findings = []
        
        # Check if file is text-based (skip binary files)
        if not self._is_text_file(filepath):
            return True, "OK", []  # Skip binary files for now
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().lower()
        except Exception as e:
            # If we can't read the file, allow it (might be binary or permission issue)
            return True, f"Could not inspect file: {str(e)}", []
        
        # Check for sensitive keywords
        for keyword in self.sensitive_keywords:
            if keyword.lower() in content:
                findings.append(f"Sensitive keyword found: '{keyword}'")
        
        # Check for sensitive patterns
        for pattern in self.sensitive_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                findings.append(f"Sensitive pattern matched: '{pattern}' ({len(matches)} matches)")
        
        # Check for data type patterns
        for data_type in self.enabled_data_types:
            if data_type in self.data_patterns:
                pattern = self.data_patterns[data_type]
                matches = re.findall(pattern, content)
                if matches:
                    findings.append(f"{data_type.replace('_', ' ').title()} detected ({len(matches)} matches)")
        
        if findings:
            return False, "Sensitive data found in file", findings
        
        return True, "OK", []
    
    def _is_text_file(self, filepath: str) -> bool:
        """
        Check if file is likely a text file.
        
        Args:
            filepath: Path to the file
            
        Returns:
            True if file appears to be text-based
        """
        # Check extension
        text_extensions = ['.txt', '.py', '.js', '.json', '.xml', '.html', '.css', 
                          '.md', '.log', '.csv', '.conf', '.config', '.ini', '.yaml', 
                          '.yml', '.sh', '.bat', '.ps1', '.sql', '.java', '.cpp', 
                          '.c', '.h', '.hpp', '.go', '.rs', '.rb', '.php', '.pl']
        
        ext = os.path.splitext(filepath)[1].lower()
        if ext in text_extensions:
            return True
        
        # Try to read first few bytes to check if it's text
        try:
            with open(filepath, 'rb') as f:
                chunk = f.read(512)
                # Check if it's mostly printable ASCII
                if chunk and all(b < 128 and (b >= 32 or b in [9, 10, 13]) for b in chunk[:min(512, len(chunk))]):
                    return True
        except Exception:
            pass
        
        return False
    
    def is_inspection_enabled(self) -> bool:
        """Check if content inspection is enabled."""
        return self.inspection_config.get("enabled", False)

