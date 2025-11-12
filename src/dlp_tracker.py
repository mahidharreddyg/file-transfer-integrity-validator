"""
DLP Violations Tracker
Stores and retrieves DLP violation events for dashboard display.
"""
import os
import json
from datetime import datetime
from typing import List, Dict, Optional


DLP_VIOLATIONS_FILE = "logs/dlp_violations.json"


class DLPTracker:
    def __init__(self):
        """Initialize DLP tracker."""
        os.makedirs("logs", exist_ok=True)
        self.violations_file = DLP_VIOLATIONS_FILE
    
    def log_violation(self, filepath: str, reason: str, violation_type: str = "BLOCK",
                     details: Optional[Dict] = None) -> None:
        """
        Log a DLP violation.
        
        Args:
            filepath: Path to the file that triggered the violation
            reason: Reason for the violation
            violation_type: Type of violation (BLOCK, WARNING, etc.)
            details: Additional details dictionary
        """
        violation = {
            "timestamp": datetime.now().isoformat(),
            "filepath": filepath,
            "reason": reason,
            "type": violation_type,
            "details": details or {}
        }
        
        violations = self.get_all_violations()
        violations.append(violation)
        
        # Keep only last 1000 violations to prevent file from growing too large
        if len(violations) > 1000:
            violations = violations[-1000:]
        
        with open(self.violations_file, "w") as f:
            json.dump(violations, f, indent=2)
    
    def get_all_violations(self) -> List[Dict]:
        """
        Get all DLP violations.
        
        Returns:
            List of violation dictionaries
        """
        if not os.path.exists(self.violations_file):
            return []
        
        try:
            with open(self.violations_file, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []
    
    def get_recent_violations(self, limit: int = 50) -> List[Dict]:
        """
        Get recent DLP violations.
        
        Args:
            limit: Maximum number of violations to return
            
        Returns:
            List of recent violation dictionaries
        """
        violations = self.get_all_violations()
        return violations[-limit:]
    
    def get_violations_by_type(self, violation_type: str) -> List[Dict]:
        """
        Get violations filtered by type.
        
        Args:
            violation_type: Type of violation to filter by
            
        Returns:
            List of violation dictionaries
        """
        violations = self.get_all_violations()
        return [v for v in violations if v.get("type") == violation_type]
    
    def clear_violations(self) -> None:
        """Clear all violations (admin only)."""
        with open(self.violations_file, "w") as f:
            json.dump([], f)
    
    def get_statistics(self) -> Dict:
        """
        Get DLP violation statistics.
        
        Returns:
            Dictionary with statistics
        """
        violations = self.get_all_violations()
        
        stats = {
            "total": len(violations),
            "blocks": len([v for v in violations if v.get("type") == "BLOCK"]),
            "warnings": len([v for v in violations if v.get("type") == "WARNING"]),
            "today": len([v for v in violations if self._is_today(v.get("timestamp", ""))]),
        }
        
        return stats
    
    def _is_today(self, timestamp: str) -> bool:
        """Check if timestamp is from today."""
        try:
            dt = datetime.fromisoformat(timestamp)
            return dt.date() == datetime.now().date()
        except Exception:
            return False

