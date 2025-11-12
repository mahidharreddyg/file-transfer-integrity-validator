"""
Policy Engine for Data Loss Prevention (DLP)
Enforces file transfer policies based on file type, path, and destination.
"""
import os
import re
from typing import Tuple, List, Dict, Optional


class PolicyEngine:
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize policy engine with configuration.
        
        Args:
            config: Dictionary containing policy settings
        """
        self.config = config or {}
        self.policies = self.config.get("dlp_policies", {})
        
    def check_policy(self, filepath: str, destination: str = "") -> Tuple[bool, str]:
        """
        Check if a file transfer is allowed based on configured policies.
        
        Args:
            filepath: Path to the source file
            destination: Destination directory path
            
        Returns:
            Tuple of (allowed: bool, message: str)
        """
        # Check restricted file extensions
        restricted_extensions = self.policies.get("restricted_extensions", [])
        file_ext = os.path.splitext(filepath)[1].lower()
        if file_ext in restricted_extensions:
            return False, f"Transfer blocked: Restricted file type ({file_ext})"
        
        # Check restricted file names/patterns
        restricted_patterns = self.policies.get("restricted_patterns", [])
        filename = os.path.basename(filepath)
        for pattern in restricted_patterns:
            if re.search(pattern, filename, re.IGNORECASE):
                return False, f"Transfer blocked: File name matches restricted pattern ({pattern})"
        
        # Check restricted directories
        restricted_dirs = self.policies.get("restricted_directories", [])
        file_dir = os.path.dirname(filepath)
        for restricted_dir in restricted_dirs:
            if restricted_dir in file_dir:
                return False, f"Transfer blocked: File in restricted directory"
        
        # Check allowed destinations
        allowed_destinations = self.policies.get("allowed_destinations", [])
        if allowed_destinations and destination:
            # Normalize paths for comparison
            dest_normalized = os.path.normpath(destination)
            allowed = False
            for allowed_dest in allowed_destinations:
                if os.path.normpath(allowed_dest) in dest_normalized or dest_normalized.startswith(os.path.normpath(allowed_dest)):
                    allowed = True
                    break
            if not allowed:
                return False, f"Transfer blocked: Destination not in allowed list"
        
        # Check blocked destinations
        blocked_destinations = self.policies.get("blocked_destinations", [])
        if blocked_destinations and destination:
            dest_normalized = os.path.normpath(destination)
            for blocked_dest in blocked_destinations:
                if os.path.normpath(blocked_dest) in dest_normalized or dest_normalized.startswith(os.path.normpath(blocked_dest)):
                    return False, f"Transfer blocked: Destination is blocked"
        
        return True, "OK"
    
    def is_policy_enabled(self) -> bool:
        """Check if DLP policies are enabled."""
        return self.policies.get("enabled", False)
    
    def get_policy_summary(self) -> Dict:
        """Get a summary of current policies."""
        return {
            "enabled": self.is_policy_enabled(),
            "restricted_extensions": len(self.policies.get("restricted_extensions", [])),
            "restricted_patterns": len(self.policies.get("restricted_patterns", [])),
            "restricted_directories": len(self.policies.get("restricted_directories", [])),
            "allowed_destinations": len(self.policies.get("allowed_destinations", [])),
            "blocked_destinations": len(self.policies.get("blocked_destinations", [])),
        }

