# Quick Start Guide - DLP System

## Step 1: Install Dependencies

```bash
pip3 install -r requirements.txt
```

This installs:

- `cryptography` - For encryption and signing
- `watchdog` - For file monitoring

## Step 2: Generate Keys (if not already done)

```bash
python3 scripts/generate_keys.py
```

This creates encryption and signing keys in the `keys/` directory.

## Step 3: Create Test Files

```bash
python3 test_dlp.py
```

This creates test files that will trigger DLP policies:

- Files that should be blocked
- Files with sensitive content
- Normal files that should pass

## Step 4: Run the GUI

```bash
python3 gui.py
```

Or use the launch script:

- **macOS/Linux**: `./launch.sh`
- **Windows**: `launch.bat`

## Step 5: Test DLP Features

### Quick Test Flow:

1. **Open GUI** - The window should show 5 tabs:

   - File Transfer
   - Validation
   - Settings
   - Logs
   - **DLP Dashboard** (new!)

2. **Check Settings**:

   - Go to **Settings** tab
   - Verify role shows "ADMIN"
   - Ensure "Enable DLP Policies" is checked
   - Ensure "Enable Content Inspection" is checked

3. **Run Transfer Test**:

   - Go to **File Transfer** tab
   - Source: `test_dlp_src`
   - Destination: `test_dlp_dst`
   - Click **Start Transfer**

4. **Observe Results**:
   - You'll see desktop alerts for blocked files
   - Transfer summary shows blocked count
   - Check **DLP Dashboard** tab for violations

### Expected Results:

✅ **Should Transfer**: `normal_file.txt`

🚫 **Should Be Blocked**:

- `document.pdf` - Restricted extension
- `confidential_report.txt` - Restricted pattern
- `secret_notes.txt` - Restricted pattern
- `config.txt` - Sensitive content (password, api_key)
- `payment_info.txt` - Sensitive data (credit card, SSN)

## Step 6: View DLP Dashboard

1. Click on **DLP Dashboard** tab
2. See statistics at the top:
   - Total Violations
   - Blocks
   - Warnings
   - Today's count
3. Review violations table with:
   - Timestamp
   - File path
   - Violation type
   - Reason

## Troubleshooting

### "ModuleNotFoundError: No module named 'cryptography'"

```bash
pip3 install -r requirements.txt
```

### "No module named 'tkinter'"

**macOS**: Usually pre-installed
**Linux**: `sudo apt-get install python3-tk`
**Windows**: Usually pre-installed

### GUI doesn't open

Check Python version:

```bash
python3 --version  # Should be 3.7+
```

### No violations showing

1. Check Settings tab - ensure DLP is enabled
2. Check config/settings.json - verify policies are configured
3. Check logs/app.log for errors

## Cleanup After Testing

```bash
python3 test_dlp.py cleanup
```

This removes the test directories.

## Next Steps

- Read `TESTING_GUIDE.md` for detailed testing scenarios
- Customize policies in `config/settings.json`
- Configure email alerts (see Settings tab)
- Review `docs/` for architecture details
