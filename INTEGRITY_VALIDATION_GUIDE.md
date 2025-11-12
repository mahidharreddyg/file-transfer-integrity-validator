# Integrity Validation Guide

## Understanding the Two Tabs

### 1. **File Transfer Tab** (Transfer + Validate)

- **Purpose**: Transfer files AND validate during transfer
- **What it does**:
  - Copies files from source to destination
  - Immediately checks checksums after copying
  - Shows results: Success, Blocked (DLP), Corrupted, Missing
- **Use when**: You want to transfer files and verify they copied correctly

### 2. **Validation Tab** (Validate Existing Transfer)

- **Purpose**: Validate files that were ALREADY transferred
- **What it does**:
  - Compares source and destination folders
  - Checks if files exist in both places
  - Verifies checksums match (detects corruption/data loss)
  - Does NOT copy files - only validates what's already there
- **Use when**: Files were already copied (maybe manually, or from a previous transfer)

## When to Use Same Folders vs Different Folders

### Scenario 1: Fresh Transfer + Validation

**Use the same folders:**

1. **Transfer Tab**:

   - Source: `test_dlp_src`
   - Destination: `test_dlp_dst`
   - Click "Start Transfer"
   - This copies files AND validates them

2. **Validation Tab** (optional - to double-check):
   - Source: `test_dlp_src`
   - Destination: `test_dlp_dst`
   - Click "Validate Transfer"
   - This re-validates the already-transferred files

### Scenario 2: Validate Existing Transfer

**Use folders where files already exist:**

- Source: Folder with original files
- Destination: Folder where files were copied earlier
- Click "Validate Transfer"
- System compares what's in both folders

### Scenario 3: Test Data Loss Detection

**Create a test scenario:**

1. **First, transfer files normally:**

   - Transfer Tab: `test_dlp_src` → `test_dlp_dst`
   - Files get copied successfully

2. **Then, manually corrupt a file:**

   ```bash
   # Edit a file in destination to simulate corruption
   echo "corrupted data" > test_dlp_dst/normal_file.txt
   ```

3. **Now validate:**
   - Validation Tab: `test_dlp_src` → `test_dlp_dst`
   - System will detect the corrupted file!

## Quick Test Scenarios

### Test 1: Normal Transfer (Both Tabs)

```
1. Reset test files: python3 test_dlp.py reset
2. Transfer Tab:
   - Source: test_dlp_src
   - Destination: test_dlp_dst
   - Click "Start Transfer"
   - Result: Shows successful transfers, blocked files, etc.

3. Validation Tab (optional):
   - Source: test_dlp_src
   - Destination: test_dlp_dst
   - Click "Validate Transfer"
   - Result: Confirms all transferred files are OK
```

### Test 2: Detect Corruption

```
1. Transfer files first (Transfer Tab)
2. Manually corrupt a file:
   echo "wrong data" > test_dlp_dst/normal_file.txt
3. Validation Tab:
   - Source: test_dlp_src
   - Destination: test_dlp_dst
   - Click "Validate Transfer"
   - Result: Shows normal_file.txt as CORRUPTED
```

### Test 3: Detect Missing Files

```
1. Transfer files first (Transfer Tab)
2. Delete a file from destination:
   rm test_dlp_dst/normal_file.txt
3. Validation Tab:
   - Source: test_dlp_src
   - Destination: test_dlp_dst
   - Click "Validate Transfer"
   - Result: Shows normal_file.txt as MISSING
```

## Key Differences

| Feature                   | Transfer Tab | Validation Tab |
| ------------------------- | ------------ | -------------- |
| Copies files              | ✅ Yes       | ❌ No          |
| Validates during transfer | ✅ Yes       | ❌ No          |
| Validates existing files  | ❌ No        | ✅ Yes         |
| Shows DLP blocks          | ✅ Yes       | ❌ No          |
| Shows corruption          | ✅ Yes       | ✅ Yes         |
| Shows missing files       | ✅ Yes       | ✅ Yes         |

## Best Practice

**For most use cases:**

- Use **Transfer Tab** - it does everything (copy + validate)
- Use **Validation Tab** only when:
  - Files were copied outside the system
  - You want to re-validate after manual changes
  - You suspect corruption and want to check

## Summary

**Same folders?**

- ✅ Yes, you can use the same folders
- Transfer Tab: Copies and validates
- Validation Tab: Validates what's already there

**Different folders?**

- ✅ Also fine
- Use when you have files in different locations
- Validation Tab compares any two folders

The integrity validation works with **any folders** - it just compares what's in source vs destination!
