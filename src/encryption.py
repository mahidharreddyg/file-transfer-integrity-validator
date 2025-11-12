"""
Encryption Module for Data Loss Prevention (DLP)
Provides secure file encryption/decryption for sensitive file transfers.
"""
import os
from cryptography.fernet import Fernet
from typing import Optional


class EncryptionManager:
    def __init__(self, key_file: str = "keys/encryption.key"):
        """
        Initialize encryption manager.
        
        Args:
            key_file: Path to file storing the encryption key
        """
        self.key_file = key_file
        self.key = self._load_or_generate_key()
        self.cipher = Fernet(self.key)
    
    def _load_or_generate_key(self) -> bytes:
        """
        Load encryption key from file or generate a new one.
        
        Returns:
            Encryption key as bytes
        """
        os.makedirs(os.path.dirname(self.key_file) if os.path.dirname(self.key_file) else ".", exist_ok=True)
        
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as f:
                return f.read()
        else:
            # Generate new key
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as f:
                f.write(key)
            return key
    
    def encrypt_file(self, filepath: str, output_path: Optional[str] = None) -> str:
        """
        Encrypt a file.
        
        Args:
            filepath: Path to file to encrypt
            output_path: Optional output path (default: filepath + .encrypted)
            
        Returns:
            Path to encrypted file
        """
        if output_path is None:
            output_path = filepath + ".encrypted"
        
        with open(filepath, "rb") as f:
            file_data = f.read()
        
        encrypted_data = self.cipher.encrypt(file_data)
        
        with open(output_path, "wb") as f:
            f.write(encrypted_data)
        
        return output_path
    
    def decrypt_file(self, encrypted_filepath: str, output_path: Optional[str] = None) -> str:
        """
        Decrypt a file.
        
        Args:
            encrypted_filepath: Path to encrypted file
            output_path: Optional output path (default: remove .encrypted extension)
            
        Returns:
            Path to decrypted file
        """
        if output_path is None:
            if encrypted_filepath.endswith(".encrypted"):
                output_path = encrypted_filepath[:-10]  # Remove .encrypted
            else:
                output_path = encrypted_filepath + ".decrypted"
        
        with open(encrypted_filepath, "rb") as f:
            encrypted_data = f.read()
        
        try:
            decrypted_data = self.cipher.decrypt(encrypted_data)
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")
        
        with open(output_path, "wb") as f:
            f.write(decrypted_data)
        
        return output_path
    
    def encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data in memory."""
        return self.cipher.encrypt(data)
    
    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt data in memory."""
        return self.cipher.decrypt(encrypted_data)
    
    def is_encryption_enabled(self, config: Optional[dict] = None) -> bool:
        """
        Check if encryption is enabled in configuration.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            True if encryption is enabled
        """
        if config is None:
            return False
        return config.get("encryption", {}).get("enabled", False)
    
    def should_encrypt_file(self, filepath: str, config: Optional[dict] = None) -> bool:
        """
        Determine if a file should be encrypted based on configuration.
        
        Args:
            filepath: Path to file
            config: Configuration dictionary
            
        Returns:
            True if file should be encrypted
        """
        if not self.is_encryption_enabled(config):
            return False
        
        encryption_config = config.get("encryption", {})
        encrypt_extensions = encryption_config.get("encrypt_extensions", [])
        encrypt_patterns = encryption_config.get("encrypt_patterns", [])
        
        # Check extension
        file_ext = os.path.splitext(filepath)[1].lower()
        if file_ext in encrypt_extensions:
            return True
        
        # Check patterns
        import re
        filename = os.path.basename(filepath)
        for pattern in encrypt_patterns:
            if re.search(pattern, filename, re.IGNORECASE):
                return True
        
        return False

