# File Transfer Integrity Validator with DLP - Complete Project Details

## Project Overview

**Project Name:** File Transfer Integrity Validator with Data Loss Prevention (DLP)

**Type:** Hybrid Data Integrity & Data Loss Prevention System

**Technology Stack:** Python 3.7+, Tkinter (GUI), Cryptography, Watchdog

**Purpose:** A comprehensive system that combines file transfer integrity validation with advanced Data Loss Prevention capabilities to ensure secure, verified, and policy-compliant file transfers.

---

## Core Features

### 1. **File Transfer Integrity Validation** (Original System)

#### Checksum-Based Verification

- **Multiple Algorithm Support:**
  - MD5 (128-bit) - Fast but insecure
  - SHA-1 (160-bit) - Slightly stronger but broken
  - SHA-256 (256-bit) - Secure and recommended (default)
  - SHA-512 (512-bit) - Very strong, best for high-security needs

#### Data Loss Detection

- **Missing File Detection:** Identifies files that failed to transfer or were deleted
- **Corruption Detection:** Detects data corruption using checksum comparison
- **Real-time Validation:** Validates files immediately after transfer
- **Post-Transfer Validation:** Can validate existing transfers without re-copying

#### Report Generation

- **Multiple Formats:** HTML, CSV, JSON
- **Digital Signing:** Reports are cryptographically signed for authenticity
- **Status Tracking:** Shows OK, MISSING, CORRUPTED, BLOCKED status for each file
- **Tamper-Evident:** Signed reports can be verified for integrity

#### Chain Logging

- **Tamper-Evident Logging:** Blockchain-style linked hash chain
- **Event Tracking:** All operations logged with timestamps
- **Integrity Verification:** Can verify entire log chain for tampering
- **Audit Trail:** Complete history of all file operations

---

### 2. **Data Loss Prevention (DLP)** (New Features)

#### Policy-Based File Access Control

- **Extension-Based Blocking:** Block specific file types (e.g., .pdf, .docx, .xlsx)
- **Pattern-Based Blocking:** Block files matching name patterns (e.g., "confidential", "secret", "private")
- **Directory Restrictions:** Block files from specific source directories
- **Destination Control:**
  - Allowed destinations whitelist
  - Blocked destinations blacklist
- **Configurable Policies:** All policies configurable via JSON settings

#### Content Inspection & Sensitive Data Detection

- **Keyword Scanning:** Detects sensitive keywords (password, api_key, secret, etc.)
- **Pattern Matching:** Regex-based pattern detection for sensitive data
- **Data Type Detection:**
  - Credit card numbers (format: XXXX-XXXX-XXXX-XXXX)
  - Social Security Numbers (format: XXX-XX-XXXX)
  - Email addresses
- **Text File Analysis:** Automatically detects and scans text-based files
- **Binary File Handling:** Skips binary files to avoid false positives

#### Encryption for Secure Transfer

- **Automatic Encryption:** Encrypts sensitive files before transfer
- **Fernet Symmetric Encryption:** Uses cryptography.fernet for secure encryption
- **Key Management:** Automatic key generation and secure storage
- **Selective Encryption:** Only encrypts files matching criteria (extensions/patterns)
- **Transparent Process:** Encryption happens automatically during transfer

#### Alert System

- **Desktop Notifications:** Real-time popup alerts for DLP violations
- **Email Alerts:** SMTP-based email notifications (configurable)
- **Alert Levels:** BLOCK, WARNING, INFO
- **Detailed Information:** Alerts include file path, reason, and violation type

#### DLP Dashboard

- **Real-time Statistics:**
  - Total violations
  - Blocks vs Warnings
  - Today's violation count
- **Violations Table:**
  - Timestamp
  - File path
  - Violation type
  - Reason
- **Filtering:** View violations by type
- **Admin Controls:** Clear violations (admin only)

#### Role-Based Access Control (RBAC)

- **User Roles:** Admin and User
- **Admin Privileges:**
  - Modify DLP policies
  - Configure content inspection
  - Enable/disable encryption
  - Clear violation history
  - Modify all settings
- **User Privileges:**
  - View violations
  - Run transfers
  - View reports
  - Read-only access to settings

---

## System Architecture

### Component Structure

#### Core Modules (src/)

1. **checksum_utils.py**

   - File checksum calculation
   - Checksum comparison
   - Manifest generation

2. **transfer_validator.py**

   - Transfer validation logic
   - Missing/corrupted file detection
   - Directory comparison

3. **report_generator.py**

   - HTML report generation
   - CSV export
   - JSON export
   - Multi-format support

4. **signing.py**

   - RSA digital signatures
   - Report signing
   - Signature verification
   - Key management

5. **chain_logger.py**

   - Tamper-evident logging
   - Hash chain implementation
   - Chain verification
   - Event tracking

6. **watchdog_monitor.py**

   - Real-time file monitoring
   - File system events
   - Change detection

7. **logger.py**

   - Application logging
   - Log file management
   - Log rotation

8. **config_manager.py**
   - Configuration loading
   - Settings persistence
   - JSON configuration

#### DLP Modules

9. **policy_engine.py**

   - Policy evaluation
   - File access control
   - Extension/pattern matching
   - Destination validation

10. **content_inspector.py**

    - Content scanning
    - Keyword detection
    - Pattern matching
    - Data type detection

11. **alert_system.py**

    - Desktop notifications
    - Email alerts
    - Alert routing
    - Notification management

12. **encryption.py**

    - File encryption/decryption
    - Key management
    - Encryption decision logic

13. **dlp_tracker.py**
    - Violation logging
    - Statistics generation
    - Violation history
    - Data persistence

---

## User Interface (GUI)

### Tabs

1. **File Transfer Tab**

   - Source/destination folder selection
   - Transfer execution
   - Real-time progress bar
   - Status updates
   - DLP integration
   - Checksum validation
   - Summary display

2. **Validation Tab**

   - Post-transfer validation
   - Source/destination comparison
   - Missing file detection
   - Corruption detection
   - Report generation

3. **Settings Tab**

   - Checksum algorithm selection
   - Report format selection
   - DLP policy configuration (admin)
   - Content inspection settings (admin)
   - Encryption settings (admin)
   - Alert configuration (admin)
   - Role indicator
   - Test file management

4. **Logs Tab**

   - Application log viewer
   - Log refresh
   - Chain verification
   - Log folder access

5. **DLP Dashboard Tab** (New)
   - Violation statistics
   - Violations table
   - Filtering options
   - Refresh functionality
   - Admin clear function

### GUI Features

- **Dark Theme:** Modern dark UI
- **Progress Indicators:** Real-time transfer progress
- **Status Colors:** Visual status indicators (green/orange/red)
- **Error Handling:** User-friendly error messages
- **Report Integration:** Direct report opening
- **Responsive Design:** 1000x600 window size

---

## Workflow & Process Flow

### File Transfer Process

1. **Pre-Transfer Checks:**

   - DLP Policy Evaluation
   - Content Inspection
   - Encryption Decision

2. **Transfer Execution:**

   - File Copying
   - Encryption (if needed)
   - Watchdog Monitoring

3. **Post-Transfer Validation:**

   - Checksum Calculation
   - Comparison
   - Corruption Detection
   - Missing File Detection

4. **Reporting & Logging:**
   - Report Generation
   - Digital Signing
   - Chain Logging
   - Violation Tracking

### DLP Enforcement Flow

1. **Policy Check:**

   - Extension validation
   - Pattern matching
   - Directory restrictions
   - Destination validation

2. **Content Inspection:**

   - File content scanning
   - Keyword detection
   - Pattern matching
   - Data type detection

3. **Action Decision:**

   - Allow transfer
   - Block transfer
   - Encrypt and transfer
   - Alert and block

4. **Violation Handling:**
   - Log violation
   - Send alerts
   - Update dashboard
   - Chain log entry

---

## Configuration

### Settings File (config/settings.json)

```json
{
  "checksum_algorithm": "sha512",
  "report_formats": ["html", "csv", "json"],
  "log_level": "INFO",
  "user_role": "admin",
  "dlp_policies": {
    "enabled": true,
    "restricted_extensions": [".pdf", ".docx", ".xlsx"],
    "restricted_patterns": ["confidential", "secret", "private"],
    "restricted_directories": [],
    "allowed_destinations": [],
    "blocked_destinations": []
  },
  "content_inspection": {
    "enabled": true,
    "sensitive_keywords": ["password", "confidential", "api key"],
    "sensitive_patterns": ["\\bpassword\\s*[:=]\\s*\\S+"],
    "enabled_data_types": ["credit_card", "ssn"]
  },
  "encryption": {
    "enabled": true,
    "encrypt_extensions": [".pdf", ".docx"],
    "encrypt_patterns": ["confidential", "secret"]
  },
  "alerts": {
    "desktop_notifications": true,
    "email_enabled": false,
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587
  }
}
```

---

## Security Features

### Cryptographic Security

- **Digital Signatures:** RSA-PSS with SHA-256
- **Encryption:** Fernet (symmetric encryption)
- **Key Management:** Secure key storage
- **Hash Algorithms:** SHA-256, SHA-512

### Tamper Detection

- **Chain Logging:** Blockchain-style hash chain
- **Report Signing:** Cryptographically signed reports
- **Integrity Verification:** Chain verification capability

### Access Control

- **Role-Based Access:** Admin/User separation
- **Policy Enforcement:** Configurable access policies
- **Audit Trail:** Complete operation logging

---

## Testing & Demo Capabilities

### Test File Management

1. **DLP Test Files** (`test_dlp_src/`, `test_dlp_dst/`)

   - Purpose: DLP policy testing
   - Files: Restricted extensions, sensitive content, patterns
   - Reset: GUI button or `python3 test_dlp.py reset`

2. **Integrity Test Files** (`tests/test_data/src/`, `test_transfer/`)
   - Purpose: Checksum validation testing
   - Files: Normal files + pre-corrupted file
   - Reset: GUI button or `python3 setup_integrity_tests.py reset`

### Test Scenarios

1. **DLP Blocking:**

   - Extension-based blocks
   - Pattern-based blocks
   - Content-based blocks
   - Destination restrictions

2. **Integrity Validation:**

   - Normal transfer validation
   - Corruption detection
   - Missing file detection
   - Post-transfer validation

3. **Encryption:**
   - Automatic encryption
   - Encrypted file transfer
   - Decryption verification

---

## Dependencies

### Python Packages (requirements.txt)

- `cryptography==46.0.2` - Encryption and signing
- `watchdog==6.0.0` - File system monitoring
- `cffi==2.0.0` - Cryptography support
- `pycparser==2.23` - Parser support

### Built-in Libraries

- `tkinter` - GUI framework
- `hashlib` - Checksum algorithms
- `json` - Configuration
- `os`, `shutil` - File operations
- `threading` - Async operations
- `subprocess` - External commands

---

## File Structure

```
file-transfer-integrity-validator/
├── src/
│   ├── checksum_utils.py
│   ├── transfer_validator.py
│   ├── report_generator.py
│   ├── signing.py
│   ├── chain_logger.py
│   ├── watchdog_monitor.py
│   ├── logger.py
│   ├── config_manager.py
│   ├── policy_engine.py (DLP)
│   ├── content_inspector.py (DLP)
│   ├── alert_system.py (DLP)
│   ├── encryption.py (DLP)
│   └── dlp_tracker.py (DLP)
├── config/
│   └── settings.json
├── keys/
│   ├── private.pem
│   ├── public.pem
│   └── encryption.key
├── logs/
│   ├── app.log
│   ├── chain.log
│   └── dlp_violations.json
├── reports/
│   └── report_*.html/csv/json + .sig
├── tests/
│   └── test_data/
│       └── src/
├── test_transfer/
├── test_dlp_src/
├── test_dlp_dst/
├── gui.py
├── main.py
├── test_dlp.py
├── setup_integrity_tests.py
└── requirements.txt
```

---

## Use Cases

1. **Enterprise File Transfer:**

   - Secure file transfers with integrity verification
   - Policy enforcement for sensitive data
   - Compliance with data protection regulations

2. **Data Migration:**

   - Verify data integrity during migration
   - Detect corruption or data loss
   - Generate audit reports

3. **Backup Verification:**

   - Validate backup integrity
   - Detect backup corruption
   - Ensure data recoverability

4. **Compliance & Auditing:**

   - DLP policy enforcement
   - Audit trail generation
   - Tamper-evident logging

5. **Sensitive Data Protection:**
   - Prevent unauthorized data transfer
   - Encrypt sensitive files
   - Monitor data access

---

## Key Innovations

1. **Hybrid System:** Combines integrity validation with DLP in one platform
2. **Tamper-Evident Logging:** Blockchain-style hash chain for audit trails
3. **Real-time Monitoring:** Watchdog integration for live file monitoring
4. **Multi-layer Security:** Policy + Content + Encryption + Validation
5. **User-Friendly GUI:** Complex security made accessible
6. **Comprehensive Reporting:** Multiple formats with digital signatures

---

## Technical Specifications

- **Language:** Python 3.7+
- **GUI Framework:** Tkinter
- **Cryptography:** cryptography library (Fernet, RSA)
- **File Monitoring:** watchdog library
- **Hash Algorithms:** MD5, SHA-1, SHA-256, SHA-512
- **Encryption:** Fernet (AES-128 in CBC mode)
- **Signing:** RSA-PSS with SHA-256
- **Platform:** Cross-platform (Windows, macOS, Linux)

---

## Performance Features

- **Asynchronous Operations:** Threading for non-blocking GUI
- **Progress Tracking:** Real-time progress bars
- **Efficient Scanning:** Text file detection to skip binaries
- **Optimized Validation:** Parallel checksum calculation
- **Memory Efficient:** Stream-based file operations

---

## Future Enhancement Possibilities

1. Network transfer support (FTP, SFTP, S3)
2. Cloud storage integration
3. Machine learning for anomaly detection
4. Advanced pattern recognition
5. Multi-user support with database backend
6. Web-based dashboard
7. API for automation
8. Integration with SIEM systems

---

## Summary

This is a comprehensive **Hybrid Data Integrity & Data Loss Prevention System** that provides:

✅ **Data Integrity:** Checksum-based verification, corruption detection, missing file detection
✅ **Data Loss Prevention:** Policy enforcement, content inspection, encryption, blocking
✅ **Security:** Digital signatures, tamper-evident logging, role-based access
✅ **Usability:** Modern GUI, comprehensive reporting, easy configuration
✅ **Compliance:** Audit trails, violation tracking, detailed logging

The system successfully combines traditional file integrity validation with modern DLP capabilities, creating a powerful solution for secure file transfer management.
