# DLP System Testing Guide

This guide will help you test all the DLP (Data Loss Prevention) features.

## Prerequisites

1. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

2. **Generate Encryption Keys** (if not already done)
   ```bash
   python3 scripts/generate_keys.py
   ```

## Quick Start

### 1. Create Test Files

Run the test file generator:

```bash
python3 test_dlp.py
```

This creates test files in `test_dlp_src/` directory that will trigger various DLP policies.

### 2. Run the GUI

```bash
python3 gui.py
```

Or use the launch script:

- **macOS/Linux**: `./launch.sh`
- **Windows**: `launch.bat`

## Testing Scenarios

### Test 1: Policy-Based Blocking

**What to test**: Files blocked by extension or name patterns

1. In the GUI, go to **Settings** tab
2. Verify you're logged in as **admin** (check "Current Role" at top)
3. Ensure "Enable DLP Policies" is checked
4. Go to **File Transfer** tab
5. Set Source: `test_dlp_src`
6. Set Destination: `test_dlp_dst`
7. Click **Start Transfer**

**Expected Results**:

- ✅ `normal_file.txt` - Should transfer successfully
- 🚫 `document.pdf` - Should be BLOCKED (restricted extension)
- 🚫 `confidential_report.txt` - Should be BLOCKED (restricted pattern)
- 🚫 `secret_notes.txt` - Should be BLOCKED (restricted pattern)

**Check**:

- Transfer summary shows blocked files
- DLP Dashboard shows violations
- Desktop alert appears for each block

### Test 2: Content Inspection

**What to test**: Files blocked due to sensitive content

1. Ensure "Enable Content Inspection" is checked in Settings
2. Run transfer from `test_dlp_src` to `test_dlp_dst`

**Expected Results**:

- 🚫 `config.txt` - Should be BLOCKED (contains "password" and "api_key")
- 🚫 `payment_info.txt` - Should be BLOCKED (contains credit card and SSN)

**Check**:

- DLP Dashboard shows content violations
- Violation reason mentions "Sensitive data found"

### Test 3: Encryption

**What to test**: Sensitive files are encrypted during transfer

1. Enable "Enable Encryption for Sensitive Files" in Settings
2. Run transfer

**Expected Results**:

- `sensitive_data.docx` - Should be encrypted (file ends with `.encrypted`)

**Check**:

- Destination folder contains `.encrypted` files
- Logs show "Encrypted file" messages

### Test 4: DLP Dashboard

**What to test**: Violations tracking and statistics

1. After running transfers, go to **DLP Dashboard** tab
2. Check statistics at the top
3. Review violations table

**Expected Results**:

- Statistics show total violations, blocks, warnings
- Table shows all blocked files with timestamps
- Can filter and view details

### Test 5: Role-Based Access

**What to test**: Admin vs User permissions

1. In `config/settings.json`, change `"user_role": "user"`
2. Restart GUI
3. Go to Settings tab

**Expected Results**:

- DLP Settings section is NOT visible (admin only)
- DLP Dashboard "Clear All" button is NOT visible (admin only)

3. Change back to `"user_role": "admin"` and restart

### Test 6: Alert System

**What to test**: Desktop and email notifications

1. Ensure "Enable Desktop Notifications" is checked
2. Run transfer with blocked files

**Expected Results**:

- Desktop alert popup appears for each blocked file
- Alert shows file name and reason

**Email Alerts** (Optional):

1. Configure email in `config/settings.json`:
   ```json
   "alerts": {
     "email_enabled": true,
     "smtp_server": "smtp.gmail.com",
     "smtp_port": 587,
     "smtp_user": "your-email@gmail.com",
     "smtp_password": "your-app-password",
     "email_recipients": ["admin@example.com"]
   }
   ```
2. Run transfer - emails will be sent for violations

## Manual Testing Checklist

- [ ] Policy-based blocking works (extensions, patterns)
- [ ] Content inspection detects sensitive keywords
- [ ] Content inspection detects patterns (credit cards, SSN)
- [ ] Encryption works for sensitive files
- [ ] Desktop alerts appear on violations
- [ ] DLP Dashboard shows violations
- [ ] Statistics are accurate
- [ ] Chain logger records violations
- [ ] Admin can modify DLP settings
- [ ] User cannot modify DLP settings
- [ ] Reports include "BLOCKED" status
- [ ] Normal files transfer successfully

## Cleanup

After testing, clean up test files:

```bash
python3 test_dlp.py cleanup
```

## Troubleshooting

### Import Errors

If you see `ModuleNotFoundError: No module named 'cryptography'`:

```bash
pip install -r requirements.txt
```

### No Violations Showing

1. Check that DLP policies are enabled in Settings
2. Verify test files match restricted patterns
3. Check logs/app.log for details

### Encryption Not Working

1. Ensure encryption key exists: `keys/encryption.key`
2. Check that encryption is enabled in Settings
3. Verify file matches encryption criteria in config

### GUI Not Starting

1. Check Python version: `python3 --version` (should be 3.7+)
2. Verify tkinter is installed: `python3 -m tkinter`
3. Check for syntax errors: `python3 -m py_compile gui.py`

## Advanced Testing

### Test Custom Policies

Edit `config/settings.json` to add custom policies:

```json
"dlp_policies": {
  "enabled": true,
  "restricted_extensions": [".pdf", ".docx", ".xlsx", ".zip"],
  "restricted_patterns": ["confidential", "secret", "private", "internal"],
  "allowed_destinations": ["/safe/destination"],
  "blocked_destinations": ["/unsafe/destination"]
}
```

### Test Custom Content Patterns

```json
"content_inspection": {
  "enabled": true,
  "sensitive_keywords": ["password", "api_key", "token", "secret"],
  "sensitive_patterns": [
    "\\bpassword\\s*[:=]\\s*\\S+",
    "\\bapi[_-]?key\\s*[:=]\\s*\\S+"
  ],
  "enabled_data_types": ["credit_card", "ssn", "email"]
}
```

## Next Steps

After testing, you can:

1. Customize policies for your use case
2. Configure email alerts
3. Set up allowed/blocked destinations
4. Adjust content inspection patterns
5. Enable encryption for specific file types
