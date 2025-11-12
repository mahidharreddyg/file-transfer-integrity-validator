"""
Alert System for Data Loss Prevention (DLP)
Sends notifications via email and desktop alerts when DLP violations occur.
"""
import os
import smtplib
import tkinter as tk
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Optional, List
from datetime import datetime


class AlertSystem:
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize alert system with configuration.
        
        Args:
            config: Dictionary containing alert settings
        """
        self.config = config or {}
        self.alert_config = self.config.get("alerts", {})
        
    def send_alert(self, level: str, message: str, details: Optional[Dict] = None, 
                   root_window: Optional[tk.Tk] = None) -> bool:
        """
        Send alert via configured channels (email, desktop notification).
        
        Args:
            level: Alert level (BLOCK, WARNING, INFO)
            message: Alert message
            details: Additional details dictionary
            root_window: Tkinter root window for desktop notifications
            
        Returns:
            True if alert was sent successfully
        """
        success = True
        
        # Desktop notification
        if self.alert_config.get("desktop_notifications", True):
            try:
                self._show_desktop_alert(level, message, root_window)
            except Exception as e:
                print(f"Failed to show desktop alert: {e}")
                success = False
        
        # Email notification
        if self.alert_config.get("email_enabled", False) and level in ["BLOCK", "WARNING"]:
            try:
                self._send_email_alert(level, message, details)
            except Exception as e:
                print(f"Failed to send email alert: {e}")
                success = False
        
        return success
    
    def _show_desktop_alert(self, level: str, message: str, root_window: Optional[tk.Tk] = None):
        """Show desktop notification using tkinter messagebox."""
        import tkinter.messagebox as messagebox
        
        # Use root window if provided, otherwise create a temporary one
        if root_window:
            root = root_window
        else:
            root = tk.Tk()
            root.withdraw()  # Hide the main window
        
        title = f"DLP Alert - {level}"
        
        if level == "BLOCK":
            messagebox.showerror(title, message, parent=root if root_window else None)
        elif level == "WARNING":
            messagebox.showwarning(title, message, parent=root if root_window else None)
        else:
            messagebox.showinfo(title, message, parent=root if root_window else None)
        
        if not root_window:
            root.destroy()
    
    def _send_email_alert(self, level: str, message: str, details: Optional[Dict] = None):
        """Send email alert to configured recipients."""
        if not self.alert_config.get("email_enabled", False):
            return
        
        smtp_server = self.alert_config.get("smtp_server", "smtp.gmail.com")
        smtp_port = self.alert_config.get("smtp_port", 587)
        smtp_user = self.alert_config.get("smtp_user", "")
        smtp_password = self.alert_config.get("smtp_password", "")
        recipients = self.alert_config.get("email_recipients", [])
        
        if not smtp_user or not smtp_password or not recipients:
            return  # Email not configured
        
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = smtp_user
            msg['To'] = ", ".join(recipients)
            msg['Subject'] = f"DLP Alert - {level}: File Transfer Blocked"
            
            # Build email body
            body = f"""
DLP Alert - {level}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Message: {message}
"""
            if details:
                body += "\nDetails:\n"
                for key, value in details.items():
                    body += f"  {key}: {value}\n"
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.send_message(msg)
            
        except Exception as e:
            raise Exception(f"Email alert failed: {str(e)}")
    
    def is_email_enabled(self) -> bool:
        """Check if email alerts are enabled and configured."""
        return (self.alert_config.get("email_enabled", False) and 
                self.alert_config.get("smtp_user") and 
                self.alert_config.get("smtp_password") and
                self.alert_config.get("email_recipients", []))

